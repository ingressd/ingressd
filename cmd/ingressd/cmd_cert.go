// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ingressd/ingressd/internal/edgecert"
	"github.com/ingressd/ingressd/internal/pki"
	"github.com/ingressd/ingressd/internal/secrets"
)

func newCertCmd(e *env) *cobra.Command {
	cmd := &cobra.Command{Use: "cert", Short: "Edge certificates and the Origin CA"}
	cmd.AddCommand(newCertListCmd(e), newCertOriginCmd(e))
	return cmd
}

// newCertListCmd lists the public (edge) certificates Caddy holds in its storage.
func newCertListCmd(e *env) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the edge's public certificates (SANs, issuer, expiry)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			certs, err := edgecert.List(filepath.Join(e.stateDir, "caddy"))
			if err != nil {
				return err
			}
			if len(certs) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No certificates yet.")
				return nil
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "SANS\tISSUER\tEXPIRES\tDAYS LEFT")
			now := time.Now()
			for _, c := range certs {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%d\n", strings.Join(edgecert.SANs(c), ","), edgecert.IssuerName(c),
					c.NotAfter.UTC().Format("2006-01-02"), int(c.NotAfter.Sub(now).Hours()/24))
			}
			return tw.Flush()
		},
	}
}

func newCertOriginCmd(e *env) *cobra.Command {
	cmd := &cobra.Command{Use: "origin", Short: "Issue and manage Origin CA certificates for origin servers"}
	cmd.AddCommand(newOriginIssueCmd(e), newOriginSignCSRCmd(e), newOriginListCmd(e),
		newOriginRevokeCmd(e), newOriginSnippetCmd())
	return cmd
}

// originCA loads (creating on first use) the Origin CA. save persists the
// secrets and inventory and records them in history.
type originCA struct {
	e       *env
	st      *secrets.Store
	ca      *pki.CA
	inv     *pki.Inventory
	created bool
}

func (e *env) originCA() (*originCA, error) {
	cfg, err := e.loadConfig()
	if err != nil {
		return nil, err
	}
	if !cfg.Certificates.OriginCA.Enabled {
		return nil, errors.New("the Origin CA is disabled: set certificates.origin_ca.enabled: true")
	}
	st, err := e.openSecrets()
	if err != nil {
		return nil, err
	}
	ca, created, err := pki.LoadOrInit(st, cfg.Certificates.OriginCA.CommonName)
	if err != nil {
		return nil, err
	}
	inv, err := pki.LoadInventory(e.configDir)
	if err != nil {
		return nil, err
	}
	return &originCA{e: e, st: st, ca: ca, inv: inv, created: created}, nil
}

func (o *originCA) save(secretsChanged bool, msg string) error {
	if secretsChanged || o.created {
		if err := o.st.Save(); err != nil {
			return err
		}
	}
	o.inv.SyncCA(o.ca)
	if err := o.inv.Save(o.e.configDir); err != nil {
		return err
	}
	paths := []string{pki.InventoryFile}
	if secretsChanged || o.created {
		paths = append(paths, "secrets.age")
	}
	_, err := o.e.repo().Commit(os.Getenv("USER"), msg, paths...)
	return err
}

func newOriginIssueCmd(e *env) *cobra.Command {
	var (
		req              pki.IssueRequest
		out, pfxPass     string
		pfxPassFromStdin bool
	)
	cmd := &cobra.Command{
		Use:   "issue --san <name|ip> [--san ...]",
		Short: "Issue an origin server certificate and key (key is not kept on the edge)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if pfxPassFromStdin {
				b, err := io.ReadAll(cmd.InOrStdin())
				if err != nil {
					return err
				}
				pfxPass = strings.TrimRight(string(b), "\r\n")
			}
			o, err := e.originCA()
			if err != nil {
				return err
			}
			iss, err := o.ca.Issue(req, time.Now())
			if err != nil {
				return err
			}
			files, err := o.ca.WriteBundle(out, iss, pfxPass)
			if err != nil {
				return err
			}
			r := o.inv.Add(iss, time.Now())
			if err := o.save(false, "Issue origin certificate "+r.Serial); err != nil {
				return err
			}
			printIssued(cmd.OutOrStdout(), r, files)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringSliceVar(&req.SANs, "san", nil, "DNS name, *.wildcard or IP address (repeatable or comma-separated)")
	f.IntVar(&req.Days, "days", pki.DefaultLeafDays, "validity in days")
	f.StringVar(&req.KeyType, "key-type", pki.KeyECDSAP256, "key type: "+strings.Join(pki.KeyTypes, ", "))
	f.StringVar(&out, "out", ".", "directory to write origin.crt, origin.key, origin.pfx and the CA bundles")
	f.StringVar(&pfxPass, "pfx-password", "", "password for origin.pfx (prefer --pfx-password-stdin)")
	f.BoolVar(&pfxPassFromStdin, "pfx-password-stdin", false, "read the origin.pfx password from stdin")
	_ = cmd.MarkFlagRequired("san")
	return cmd
}

func newOriginSignCSRCmd(e *env) *cobra.Command {
	var (
		sans []string
		days int
		out  string
	)
	cmd := &cobra.Command{
		Use:   "sign-csr <csr.pem|->",
		Short: "Issue an origin certificate for a CSR (the private key never touches the edge)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var csr []byte
			var err error
			if args[0] == "-" {
				csr, err = io.ReadAll(cmd.InOrStdin())
			} else {
				csr, err = os.ReadFile(args[0])
			}
			if err != nil {
				return err
			}
			o, err := e.originCA()
			if err != nil {
				return err
			}
			iss, err := o.ca.SignCSR(csr, sans, days, time.Now())
			if err != nil {
				return err
			}
			r := o.inv.Add(iss, time.Now())
			if out == "" {
				if _, err := cmd.OutOrStdout().Write(iss.ChainPEM()); err != nil {
					return err
				}
				return o.save(false, "Sign origin CSR "+r.Serial)
			}
			files, err := o.ca.WriteBundle(out, iss, "")
			if err != nil {
				return err
			}
			if err := o.save(false, "Sign origin CSR "+r.Serial); err != nil {
				return err
			}
			printIssued(cmd.OutOrStdout(), r, files)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringSliceVar(&sans, "san", nil, "extra SANs in addition to those in the CSR")
	f.IntVar(&days, "days", pki.DefaultLeafDays, "validity in days")
	f.StringVar(&out, "out", "", "directory to write origin.crt and the CA bundles (default: print the chain)")
	return cmd
}

func printIssued(w io.Writer, r pki.Record, files []string) {
	fmt.Fprintf(w, "Issued %s for %s, valid until %s.\n", r.Serial, strings.Join(r.SANs, ", "), r.NotAfter.Format("2006-01-02"))
	for _, f := range files {
		fmt.Fprintf(w, "  wrote %s\n", f)
	}
}

func newOriginListCmd(e *env) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List issued origin certificates",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			inv, err := pki.LoadInventory(e.configDir)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			if c := inv.CA.OriginIssuer; c != nil {
				fmt.Fprintf(w, "Origin issuer %s (%s), expires %s\n", c.Serial, c.Subject, c.NotAfter.Format("2006-01-02"))
			}
			if c := inv.CA.EdgeClient; c != nil {
				fmt.Fprintf(w, "Edge client   %s (%s), expires %s\n", c.Serial, c.Subject, c.NotAfter.Format("2006-01-02"))
			}
			if len(inv.Certificates) == 0 {
				fmt.Fprintln(w, "No origin certificates issued.")
				return nil
			}
			tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "SERIAL\tSANS\tKEY\tEXPIRES\tSTATUS")
			now := time.Now()
			for _, r := range inv.Certificates {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.Serial, strings.Join(r.SANs, ","), r.KeyType,
					r.NotAfter.Format("2006-01-02"), r.Status(inv, now))
			}
			return tw.Flush()
		},
	}
}

func newOriginRevokeCmd(e *env) *cobra.Command {
	var rotate bool
	cmd := &cobra.Command{
		Use:   "revoke <serial>",
		Short: "Record a certificate as revoked; --rotate also stops the edge trusting it",
		Long: `Records the certificate as revoked in the inventory.

The edge verifies origins against the current origin issuer and cannot check
individual serials, so a revoked certificate is still accepted until the
origin issuer is rotated. --rotate replaces the origin issuer: after the next
apply, strict origin_ca apps accept only certificates from the new issuer,
so every other active origin certificate must be re-issued.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			o, err := e.originCA()
			if err != nil {
				return err
			}
			r, err := o.inv.Revoke(args[0], time.Now())
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "Revoked %s (%s).\n", r.Serial, strings.Join(r.SANs, ", "))
			if !rotate {
				if err := o.save(false, "Revoke origin certificate "+r.Serial); err != nil {
					return err
				}
				fmt.Fprintln(w, "Note: the edge still trusts it until the origin issuer is rotated (revoke --rotate).")
				return nil
			}
			old := pki.SerialHex(o.ca.Origin.SerialNumber)
			if err := o.ca.RotateOrigin(o.st, time.Now()); err != nil {
				return err
			}
			if err := o.save(true, "Revoke origin certificate "+r.Serial+" and rotate the origin issuer"); err != nil {
				return err
			}
			fmt.Fprintf(w, "Rotated the origin issuer. Run ingressd apply to stop trusting %s.\n", old)
			var reissue []string
			for _, c := range o.inv.Certificates {
				if c.IssuedBy == old && !c.Revoked && time.Now().Before(c.NotAfter) {
					reissue = append(reissue, fmt.Sprintf("  %s  %s", c.Serial, strings.Join(c.SANs, ",")))
				}
			}
			if len(reissue) > 0 {
				fmt.Fprintln(w, "Re-issue these certificates before applying:")
				fmt.Fprintln(w, strings.Join(reissue, "\n"))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&rotate, "rotate", false, "rotate the origin issuer so the edge stops trusting the certificate")
	return cmd
}

func newOriginSnippetCmd() *cobra.Command {
	var (
		mtls bool
		dir  string
	)
	cmd := &cobra.Command{
		Use:       "snippet <" + strings.Join(pki.Servers, "|") + ">",
		Short:     "Print origin server config for an Origin CA certificate",
		Args:      cobra.ExactArgs(1),
		ValidArgs: pki.Servers,
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := pki.Snippet(args[0], dir, mtls)
			if err != nil {
				return err
			}
			fmt.Fprint(cmd.OutOrStdout(), s)
			return nil
		},
	}
	cmd.Flags().BoolVar(&mtls, "mtls", false, "also require the edge's client certificate (authenticated origin pulls)")
	cmd.Flags().StringVar(&dir, "dir", "", "where the bundle files live on the origin (default /etc/ssl/ingressd)")
	return cmd
}
