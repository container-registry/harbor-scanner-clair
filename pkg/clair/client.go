package clair

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/container-registry/harbor-scanner-clair/pkg/etc"
)

// Client communicates with clair endpoint to scan image and get detailed scan result
type Client interface {
	ScanLayer(layer Layer) error
	GetLayer(layerName string) (*LayerEnvelope, error)
	GetVulnerabilityDatabaseUpdatedAt() (*time.Time, error)
}

type client struct {
	endpointURL string
	client      *http.Client
}

// NewClient constructs a new client for Clair REST API pointing to the specified endpoint URL.
func NewClient(tlsConfig etc.TLSConfig, cfg etc.ClairConfig) (Client, error) {
	return &client{
		endpointURL: strings.TrimSuffix(cfg.URL, "/"),
		client: &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: tlsConfig.InsecureSkipVerify,
				RootCAs:            tlsConfig.RootCAs,
			},
		}},
	}, nil
}

// ScanLayer calls Clair's API to scan a layer.
func (c *client) ScanLayer(layer Layer) error {
	envelope := LayerEnvelope{
		Layer: &layer,
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.endpointURL+"/v1/layers", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	_, err = c.send(req, http.StatusCreated)
	if err != nil {
		return err
	}
	return nil
}

// GetLayer calls Clair's API to get layers with detailed vulnerability list.
func (c *client) GetLayer(layerName string) (*LayerEnvelope, error) {
	url := c.endpointURL + "/v1/layers/" + layerName + "?features&vulnerabilities"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	b, err := c.send(req, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var res LayerEnvelope
	err = json.Unmarshal(b, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c *client) GetVulnerabilityDatabaseUpdatedAt() (*time.Time, error) {
	// The timestamp used to come from a direct SELECT against Clair's Postgres
	// keyvalue table, which is why the adapter carried a database driver and a
	// DSN. That connection is gone; a nil time simply omits the metadata
	// property until the value is read over HTTP instead.
	return nil, nil
}

func (c *client) send(req *http.Request, expectedStatus int) ([]byte, error) {
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != expectedStatus {
		return nil, fmt.Errorf("unexpected status code: %d, text: %s", resp.StatusCode, string(b))
	}
	return b, nil
}
