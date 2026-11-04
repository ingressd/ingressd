// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"context"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/ingressd/ingressd/pkg/config"
)

// uploadS3 uploads the archive at file to the bucket and deletes all but
// the newest keep archives under the prefix. It returns the object key.
func uploadS3(ctx context.Context, c config.BackupS3, resolve func(string) (string, error), file string, keep int) (string, error) {
	ak, err := resolve(c.AccessKey)
	if err != nil {
		return "", err
	}
	sk, err := resolve(c.SecretKey)
	if err != nil {
		return "", err
	}
	endpoint := c.Endpoint
	secure := !c.Insecure
	if e, ok := strings.CutPrefix(endpoint, "https://"); ok {
		endpoint = e
	} else if e, ok := strings.CutPrefix(endpoint, "http://"); ok {
		endpoint, secure = e, false
	}
	endpoint = strings.TrimSuffix(endpoint, "/")
	cl, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(ak, sk, ""),
		Secure: secure,
		Region: c.Region,
	})
	if err != nil {
		return "", err
	}
	key := path.Join(c.Prefix, filepath.Base(file))
	if _, err := cl.FPutObject(ctx, c.Bucket, key, file, minio.PutObjectOptions{ContentType: "application/gzip"}); err != nil {
		return "", err
	}
	if keep <= 0 {
		return key, nil
	}
	var keys []string
	prefix := strings.TrimSuffix(c.Prefix, "/") + "/"
	if c.Prefix == "" {
		prefix = ""
	}
	for obj := range cl.ListObjects(ctx, c.Bucket, minio.ListObjectsOptions{Prefix: prefix}) {
		if obj.Err != nil {
			return key, obj.Err
		}
		if isArchive(path.Base(obj.Key)) {
			keys = append(keys, obj.Key)
		}
	}
	sort.Strings(keys)
	for len(keys) > keep {
		if err := cl.RemoveObject(ctx, c.Bucket, keys[0], minio.RemoveObjectOptions{}); err != nil {
			return key, err
		}
		keys = keys[1:]
	}
	return key, nil
}
