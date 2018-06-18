/*
Copyright 2018 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package auth

import (
	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/kube/authority"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/tlsca"

	"github.com/gravitational/trace"
)

// KubeCSR is a kubernetes CSR request
type KubeCSR struct {
	// Username is the name of the user
	Username string `json:"username"`
	// ClusterName is a name of the target cluster to generate certificate for
	ClusterName string `json:"cluster_name"`
	// CSR is a kubernetes CSR
	CSR []byte `json:"csr"`
}

// CheckAndSetDefaults checks and sets defaults
func (a *KubeCSR) CheckAndSetDefaults() error {
	if len(a.CSR) == 0 {
		return trace.BadParameter("missing parameter 'csr'")
	}
	return nil
}

// KubeCSRREsponse is a response to kubernetes CSR request
type KubeCSRResponse struct {
	// Cert is a signed certificate PEM block
	Cert []byte `json:"cert"`
	// CAS is a list of PEM block with trusted cert authorities
	CAS [][]byte `json:"cas"`
}

// ProcessKubeCSR processes CSR request against Kubernetes CA, returns
// signed certificate if sucessfull.
func (s *AuthServer) ProcessKubeCSR(req KubeCSR) (*KubeCSRResponse, error) {
	if err := req.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	// generate cluster with local kubernetes cluster
	if req.ClusterName == s.clusterName.GetClusterName() {
		log.Debugf("Generating certificate with local Kubernetes cluster.")
		cert, err := authority.ProcessCSR(req.CSR, s.kubeCACertPath)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return &KubeCSRResponse{Cert: cert.Cert, CAS: [][]byte{cert.CA}}, nil
	}
	// Certificate for remote cluster is a user certificate
	// with special provisions.
	log.Debugf("Generating certificate for remote Kubernetes cluster.")

	hostCA, err := s.GetCertAuthority(services.CertAuthID{
		Type:       services.HostCA,
		DomainName: req.ClusterName,
	}, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	user, err := s.GetUser(req.Username)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	roles, err := services.FetchRoles(user.GetRoles(), s, user.GetTraits())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	ttl := roles.AdjustSessionTTL(defaults.CertDuration)

	csr, err := tlsca.ParseCertificateRequestPEM(req.CSR)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Generate certificate, note that the roles TTL will be ignored because
	// the request is coming from "tctl auth sign" itself.
	certs, err := s.generateUserCert(certRequest{
		user:            user,
		roles:           roles,
		ttl:             ttl,
		publicKeyParsed: csr.PublicKey,
		overrideRoleTTL: false,
		// Generate a certificate restricted for
		// use against a kubernetes endpoint, and not the API server endpoint
		// otherwise proxies can generate certs for any user.
		usage: []string{teleport.UsageKubeOnly},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &KubeCSRResponse{Cert: certs.tls, CA: hostCA}, nil
}
