//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pkcs11

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/ecdsa"
	//"crypto/rsa"
	//"crypto/tls"
	//"crypto/x509"
	"fmt"
	"strings"
	//"io"
	//"net/http"
	"os"
	//"regexp"
	//"time"
	"github.com/pkg/errors"
	"github.com/zosocanuck/crypto11"
	//"github.com/sigstore/sigstore/pkg/signature"
)

const (
	CacheKey        = "signer"
	ReferenceScheme = "pkcs11://"
	ConfigFileEnv = "CRYPTO11_CONFIG"
)

type pkcs11Client struct {
    ctx *crypto11.Context
	label string
}

var (
	ErrKMSReference = errors.New("kms specification should be in the format pkcs11://LABEL")
)

/*func ValidReference(ref string) error {
	for _, re := range allREs {
		if re.MatchString(ref) {
			return nil
		}
	}
	return ErrKMSReference
}

func parseReference(resourceID string) (endpoint, keyID, alias string, err error) {
	var v []string
	for _, re := range allREs {
		v = re.FindStringSubmatch(resourceID)
		if len(v) >= 3 {
			endpoint, keyID = v[1], v[2]
			if len(v) == 4 {
				alias = v[3]
			}
			return
		}
	}
	err = errors.Errorf("invalid awskms format %q", resourceID)
	return
}*/

func newPKCS11Client(keyResourceID string) (p *pkcs11Client, err error) {
	p = &pkcs11Client{}
	p.label = strings.TrimPrefix(keyResourceID, ReferenceScheme)

	err = p.setupClient()
	if err != nil {
		return nil, err
	}

	return
}

func (p *pkcs11Client) setupClient() (err error) {
	 configFile, ok := os.LookupEnv(ConfigFileEnv)
	 if !ok {
		//fmt.Println("Please set CRYPTO11_CONFIG environment path")
		return errors.New("Please set CRYPTO11_CONFIG environment path")
	}
	p.ctx, err = crypto11.ConfigureFromFile(configFile)
	panicOnErr(err)
	return
}

/*type cmk struct {
	//KeyMetadata *kms.KeyMetadata
	PublicKey   crypto.PublicKey
}*/

/*func (c *cmk) HashFunc() crypto.Hash {
	switch *c.KeyMetadata.SigningAlgorithms[0] {
	case kms.SigningAlgorithmSpecRsassaPssSha256, kms.SigningAlgorithmSpecRsassaPkcs1V15Sha256, kms.SigningAlgorithmSpecEcdsaSha256:
		return crypto.SHA256
	case kms.SigningAlgorithmSpecRsassaPssSha384, kms.SigningAlgorithmSpecRsassaPkcs1V15Sha384, kms.SigningAlgorithmSpecEcdsaSha384:
		return crypto.SHA384
	case kms.SigningAlgorithmSpecRsassaPssSha512, kms.SigningAlgorithmSpecRsassaPkcs1V15Sha512, kms.SigningAlgorithmSpecEcdsaSha512:
		return crypto.SHA512
	default:
		return 0
	}
	//return crypto.SHA256
}*/
/*func (c *cmk) Verifier() (signature.Verifier, error) {
	switch *c.KeyMetadata.SigningAlgorithms[0] {
	case kms.SigningAlgorithmSpecRsassaPssSha256, kms.SigningAlgorithmSpecRsassaPssSha384, kms.SigningAlgorithmSpecRsassaPssSha512:
		return signature.LoadRSAPSSVerifier(c.PublicKey.(*rsa.PublicKey), c.HashFunc(), nil)
	case kms.SigningAlgorithmSpecRsassaPkcs1V15Sha256, kms.SigningAlgorithmSpecRsassaPkcs1V15Sha384, kms.SigningAlgorithmSpecRsassaPkcs1V15Sha512:
		return signature.LoadRSAPKCS1v15Verifier(c.PublicKey.(*rsa.PublicKey), c.HashFunc())
	case kms.SigningAlgorithmSpecEcdsaSha256, kms.SigningAlgorithmSpecEcdsaSha384, kms.SigningAlgorithmSpecEcdsaSha512:
		return signature.LoadECDSAVerifier(c.PublicKey.(*ecdsa.PublicKey), c.HashFunc())
	default:
		return nil, fmt.Errorf("signing algorithm unsupported")
	}
}

func (a *awsClient) keyCacheLoaderFunction(key string) (cmk interface{}, ttl time.Duration, err error) {
	return a.keyCacheLoaderFunctionWithContext(context.Background())(key)
}
func (a *awsClient) keyCacheLoaderFunctionWithContext(ctx context.Context) ttlcache.LoaderFunction {
	return func(key string) (cmk interface{}, ttl time.Duration, err error) {
		cmk, err = a.fetchCMK(ctx)
		ttl = time.Second * 300
		return
	}
}
func (a *awsClient) fetchCMK(ctx context.Context) (*cmk, error) {
	var err error
	cmk := &cmk{}
	cmk.PublicKey, err = a.fetchPublicKey(ctx)
	if err != nil {
		return nil, err
	}
	cmk.KeyMetadata, err = a.fetchKeyMetadata(ctx)
	if err != nil {
		return nil, err
	}
	return cmk, nil
}*/
func (p *pkcs11Client) getHashFunc(ctx context.Context) (crypto.Hash, error) {
	//cmk, err := a.getCMK(ctx)
	//if err != nil {
	//	return 0, err
	//}
	//return cmk.HashFunc(), nil
	return crypto.SHA256, nil
}
/*func (a *awsClient) getCMK(ctx context.Context) (*cmk, error) {
	c, err := a.keyCache.GetByLoader(CacheKey, a.keyCacheLoaderFunctionWithContext(ctx))
	if err != nil {
		return nil, err
	}

	return c.(*cmk), nil
}*/
func (p *pkcs11Client) createKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	return nil, nil
}
/*func (p *pkcs11Client) verify(ctx context.Context, sig, message io.Reader, opts ...signature.VerifyOption) error {
	/*cmk, err := a.getCMK(ctx)
	if err != nil {
		return err
	}
	verifier, err := cmk.Verifier()
	if err != nil {
		return err
	}
	return verifier.VerifySignature(sig, message, opts...)
	return nil
}*/
/*func (a *awsClient) verifyRemotely(ctx context.Context, sig []byte, digest []byte) error {
	cmk, err := a.getCMK(ctx)
	if err != nil {
		return err
	}
	alg := cmk.KeyMetadata.SigningAlgorithms[0]
	messageType := kms.MessageTypeDigest
	_, err = a.client.VerifyWithContext(ctx, &kms.VerifyInput{
		KeyId:            &a.keyID,
		Message:          digest,
		MessageType:      &messageType,
		Signature:        sig,
		SigningAlgorithm: alg,
	})
	return errors.Wrap(err, "unable to verify signature")
}*/
func (p *pkcs11Client) public(ctx context.Context) (crypto.PublicKey, error) {
	
	//Find cert
	mycrt, err := p.ctx.FindCertificate(nil, []byte (p.label), nil)
	
	ecdsapub := mycrt.PublicKey.(*ecdsa.PublicKey)
	
	return ecdsapub, err
}
func (p *pkcs11Client) sign(ctx context.Context, digest []byte, algorithm crypto.Hash) ([]byte, error) {
	

	key, err1 := p.ctx.FindKeyPair(nil, []byte (p.label))
	fmt.Printf("%v", key)
	panicOnErr(err1)

	sig, err3 := key.Sign(rand.Reader, digest, crypto.SHA256)
	panicOnErr(err3)
	return sig, nil
}
/*
func (a *awsClient) fetchPublicKey(ctx context.Context) (crypto.PublicKey, error) {
	out, err := a.client.GetPublicKeyWithContext(ctx, &kms.GetPublicKeyInput{
		KeyId: &a.keyID,
	})
	if err != nil {
		return nil, errors.Wrap(err, "getting public key")
	}
	key, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "parsing public key")
	}
	return key, nil
}

func (a *awsClient) fetchKeyMetadata(ctx context.Context) (*kms.KeyMetadata, error) {
	out, err := a.client.DescribeKeyWithContext(ctx, &kms.DescribeKeyInput{
		KeyId: &a.keyID,
	})
	if err != nil {
		return nil, errors.Wrap(err, "getting key metadata")
	}
	return out.KeyMetadata, nil
}*/
