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
	"io"
	//"strings"

	"github.com/pkg/errors"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/aws/aws-sdk-go/service/kms"
	//"github.com/ThalesIgnite/crypto11"


	"github.com/sigstore/sigstore/pkg/signature/options"
)

const (
	Algorithm_ECDSA_P256 = "ecdsa-p256"
	Algorithm_ECDSA_P384 = "ecdsa-p384"
	Algorithm_ECDSA_P521 = "ecdsa-p521"
	Algorithm_ED25519    = "ed25519"
	Algorithm_RSA_2048   = "rsa-2048"
	Algorithm_RSA_3072   = "rsa-3072"
	Algorithm_RSA_4096   = "rsa-4096"
)

var pkcs11SupportedAlgorithms []string = []string{
	Algorithm_ECDSA_P256,
	Algorithm_ECDSA_P384,
	Algorithm_ECDSA_P521,
	Algorithm_ED25519,
	Algorithm_RSA_2048,
	Algorithm_RSA_3072,
	Algorithm_RSA_4096,
}
var pkcs11SupportedHashFuncs = []crypto.Hash{
	crypto.SHA256,
	crypto.SHA384,
	crypto.SHA512,
}

type SignerVerifier struct {
	client *pkcs11Client
}

func panicOnErr(err error) {
	if err != nil {
		panic(err)
	}
}

// LoadSignerVerifier generates signatures using the specified key object in AWS KMS and hash algorithm.
//
// It also can verify signatures locally using the public key. hashFunc must not be crypto.Hash(0).
func LoadSignerVerifier(referenceStr string) (*SignerVerifier, error) {
	p := &SignerVerifier{}

	var err error
	p.client, err = newPKCS11Client(referenceStr)
	if err != nil {
		return nil, err
	}

	return p, nil
}


// SignMessage signs the provided message using PKCS#11. If the message is provided,
// this method will compute the digest according to the hash function specified
// when the Signer was created.
//
// SignMessage recognizes the following Options listed in order of preference:
//
// - WithContext()
//
// - WithDigest()
//
// - WithCryptoSignerOpts()
//
// All other options are ignored if specified.
func (p *SignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {

	var digest []byte
	var err error
	ctx := context.Background()

	for _, opt := range opts {
		opt.ApplyContext(&ctx)
		opt.ApplyDigest(&digest)
	}

	var signerOpts crypto.SignerOpts
	signerOpts, err = p.client.getHashFunc(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "getting fetching default hash function")
	}
	for _, opt := range opts {
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}

	hf := signerOpts.HashFunc()

	if len(digest) == 0 {
		digest, hf, err = signature.ComputeDigestForSigning(message, hf, pkcs11SupportedHashFuncs, opts...)
		if err != nil {
			return nil, err
		}
	}

	return p.client.sign(ctx, digest, hf)
}

// PublicKey returns the public key that can be used to verify signatures created by
// this signer. If the caller wishes to specify the context to use to obtain
// the public key, pass option.WithContext(desiredCtx).
//
// All other options are ignored if specified.
func (p *SignerVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	ctx := context.Background()
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
	}

	return p.client.public(ctx)
}

// VerifySignature verifies the signature for the given message. Unless provided
// in an option, the digest of the message will be computed using the hash function specified
// when the SignerVerifier was created.
//
// This function returns nil if the verification succeeded, and an error message otherwise.
//
// This function recognizes the following Options listed in order of preference:
//
// - WithContext()
//
// - WithDigest()
//
// - WithRemoteVerification()
//
// - WithCryptoSignerOpts()
//
// All other options are ignored if specified.
func (p *SignerVerifier) VerifySignature(sig, message io.Reader, opts ...signature.VerifyOption) (err error) {
	/*ctx := context.Background()
	var digest []byte
	var remoteVerification bool

	for _, opt := range opts {
		opt.ApplyContext(&ctx)
		opt.ApplyDigest(&digest)
		opt.ApplyRemoteVerification(&remoteVerification)
	}

	if !remoteVerification {
		return p.client.verify(ctx, sig, message, opts...)
	}

	var signerOpts crypto.SignerOpts
	signerOpts, err = p.client.getHashFunc(ctx)
	if err != nil {
		return errors.Wrap(err, "getting hash func")
	}
	for _, opt := range opts {
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}
	hf := signerOpts.HashFunc()

	if len(digest) == 0 {
		digest, _, err = signature.ComputeDigestForVerifying(message, hf, pkcs11SupportedHashFuncs, opts...)
		if err != nil {
			return err
		}
	}

	sigBytes, err := io.ReadAll(sig)
	if err != nil {
		return errors.Wrap(err, "reading signature")
	}
	return p.client.verifyRemotely(ctx, sigBytes, digest)*/
	return nil
}

// CreateKey attempts to create a new key in Vault with the specified algorithm.
func (p *SignerVerifier) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	return p.client.createKey(ctx, algorithm)
}

type cryptoSignerWrapper struct {
	ctx      context.Context
	hashFunc crypto.Hash
	sv       *SignerVerifier
	errFunc  func(error)
}

func (c cryptoSignerWrapper) Public() crypto.PublicKey {
	pk, err := c.sv.PublicKey(options.WithContext(c.ctx))
	if err != nil && c.errFunc != nil {
		c.errFunc(err)
	}
	return pk
}

func (c cryptoSignerWrapper) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashFunc := c.hashFunc
	if opts != nil {
		hashFunc = opts.HashFunc()
	}
	pkcs11Options := []signature.SignOption{
		options.WithContext(c.ctx),
		options.WithDigest(digest),
		options.WithCryptoSignerOpts(hashFunc),
	}

	return c.sv.SignMessage(nil, pkcs11Options...)
}

func (p *SignerVerifier) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	defaultHf, err := p.client.getHashFunc(ctx)
	if err != nil {
		return nil, nil, errors.Wrap(err, "getting fetching default hash function")
	}

	csw := &cryptoSignerWrapper{
		ctx:      ctx,
		sv:       p,
		hashFunc: defaultHf,
		errFunc:  errFunc,
	}

	return csw, defaultHf, nil
}

func (*SignerVerifier) SupportedAlgorithms() []string {
	return pkcs11SupportedAlgorithms
}

func (*SignerVerifier) DefaultAlgorithm() string {
	return kms.CustomerMasterKeySpecEccNistP256
}
