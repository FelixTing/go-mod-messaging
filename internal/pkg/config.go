/********************************************************************************
 *  Copyright 2020 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *******************************************************************************/

package pkg

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"reflect"
	"strconv"
)

var TlsSchemes = []string{"tcps", "ssl", "tls", "redis"}

// X509KeyPairCreator defines the function signature for creating a tls.Certificate based on PEM encoding.
type X509KeyPairCreator func(certPEMBlock []byte, keyPEMBlock []byte) (tls.Certificate, error)

// X509KeyLoader defines a function signature for loading a tls.Certificate from cert and key files.
type X509KeyLoader func(certFile string, keyFile string) (tls.Certificate, error)

type TlsConfigurationOptions struct {
	SkipCertVerify bool
	CaFile         string
	CertFile       string
	KeyFile        string
	CaPEMBlock     string
	KeyPEMBlock    string
	CertPEMBlock   string


}

func CreateDefaultTlsConfigurationOptions() TlsConfigurationOptions {
	return TlsConfigurationOptions{
		SkipCertVerify: false,
		CertFile:       "",
		KeyFile:        "",
		KeyPEMBlock:    "",
		CertPEMBlock:   "",
		CaFile: "",
		CaPEMBlock: "",
	}
}

// generateTLSForClientClientOptions creates a tls.Config which can be used when configuring the underlying MQTT client.
// If TLS is not needed then nil will be returned which can be used to signal no TLS is needed to the MQTT client.
func GenerateTLSForClientClientOptions(
	brokerURL string,
	tlsConfigurationOptions TlsConfigurationOptions,
	certCreator X509KeyPairCreator,
	certLoader X509KeyLoader) (*tls.Config, error) {

	parsedBrokerURL, err := url.Parse(brokerURL)
	if err != nil {
		return nil, NewBrokerURLErr(fmt.Sprintf("Failed to parse broker: %v", err))
	}

	for _, scheme := range TlsSchemes {
		if parsedBrokerURL.Scheme != scheme {
			continue
		}

		tlsConfig := &tls.Config{
			InsecureSkipVerify: tlsConfigurationOptions.SkipCertVerify, // nolint: gosec
		}

		if (len(tlsConfigurationOptions.CertFile) > 0 && len(tlsConfigurationOptions.KeyFile) > 0) ||
			(len(tlsConfigurationOptions.CertPEMBlock) > 0 && len(tlsConfigurationOptions.KeyPEMBlock) > 0) {
			cert, err := generateCertificate(tlsConfigurationOptions, certCreator, certLoader)
			if err != nil {
				return nil, err
			}

			tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
		}

		var caData []byte
		if len(tlsConfigurationOptions.CaFile) > 0 {
			caData, err = ioutil.ReadFile(tlsConfigurationOptions.CaFile)
			if err != nil {
				return nil, errors.New("failed to load CA file")
			}

		}
		if len(tlsConfigurationOptions.CaPEMBlock) > 0 {
			caData = []byte(tlsConfigurationOptions.CaPEMBlock)
		}
		if caData != nil {
			caCertPool := x509.NewCertPool()
			caPEMBlock, _ := pem.Decode(caData)
			if caPEMBlock == nil {
				return nil, errors.New("failed to find PEM formatted block in the CA file")
			}
			caCert, err := x509.ParseCertificate(caPEMBlock.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse CA PEM block, error: %s", err.Error())
			}
			caCertPool.AddCert(caCert)
			tlsConfig.RootCAs = caCertPool
		}

		return tlsConfig, nil
	}

	// The scheme being used either does not require TLS or is not supported with this configuration setup.
	return nil, nil
}

// generateCertificate creates a x509 certificate by either loading it from an existing cert and key files, or creates
// a cert and key from the provided PEM bytes.
func generateCertificate(
	tlsConfigurationOptions TlsConfigurationOptions,
	certCreator X509KeyPairCreator,
	certLoader X509KeyLoader) (tls.Certificate, error) {

	var cert tls.Certificate
	var err error

	if tlsConfigurationOptions.KeyPEMBlock != "" && tlsConfigurationOptions.CertPEMBlock != "" {
		cert, err = certCreator([]byte(tlsConfigurationOptions.CertPEMBlock), []byte(tlsConfigurationOptions.KeyPEMBlock))
	} else {
		cert, err = certLoader(tlsConfigurationOptions.CertFile, tlsConfigurationOptions.KeyFile)
	}

	if err != nil {
		return cert, NewCertificateErr(fmt.Sprintf("Failed loading x509 data: %v", err))
	}

	return cert, nil
}

// load by reflect to check map key and then fetch the value.
// This function ignores properties that have not been provided from the source. Therefore it is recommended to provide
// a destination struct with reasonable defaults.
//
// NOTE: This logic was borrowed from device-mqtt-go and some additional logic was added to accommodate more types.
// https://github.com/edgexfoundry/device-mqtt-go/blob/a0d50c6e03a7f7dcb28f133885c803ffad3ec502/internal/driver/config.go#L74-L101
func Load(config map[string]string, des interface{}) error {
	val := reflect.ValueOf(des).Elem()
	for i := 0; i < val.NumField(); i++ {
		typeField := val.Type().Field(i)
		valueField := val.Field(i)

		val, ok := config[typeField.Name]
		if !ok {
			// Ignore the property if the value is not provided
			continue
		}

		switch valueField.Kind() {
		case reflect.Int:
			intVal, err := strconv.Atoi(val)
			if err != nil {
				return err
			}
			valueField.SetInt(int64(intVal))
		case reflect.String:
			valueField.SetString(val)
		case reflect.Bool:
			boolVal, err := strconv.ParseBool(val)
			if err != nil {
				return err
			}
			valueField.SetBool(boolVal)
		default:
			return fmt.Errorf("none supported value type %v ,%v", valueField.Kind(), typeField.Name)
		}
	}
	return nil
}
