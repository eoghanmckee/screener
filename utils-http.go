package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
)

const (
	// JSONApplication for Content-Type headers
	JSONApplication = "application/json"
	// JSONApplicationUTF8 for Content-Type headers, UTF charset
	JSONApplicationUTF8 = JSONApplication + "; charset=UTF-8"
	// ContentType for header key
	contentType = "Content-Type"
	// ContentEncoding for header key
	contentEncoding = "Content-Encoding"
	// Header for IP Address
	realIPAddress = "X-Real-Ip"
	// Header for Authorization Token
	authToken = "authorization"
	// Header for Request ID
	requestID = "X-Request-Id"
	// Header for IP User-Agent
	userAgent string = "User-Agent"
	// Customized User-Agent
	screenerUserAgent string = "screener-http-client/1.1"
)

// ResponseMessage to be returned as JSON response
type ResponseMessage struct {
	Message string
}

// Helper to avoid dumping the authorization token in the request
func sanitizeHeaders(raw string) string {
	hasAuthHeader := regexp.MustCompile("Authorization: (.*)")
	if hasAuthHeader.MatchString(raw) {
		return hasAuthHeader.ReplaceAllString(raw, "Authorization: REDACTED")
	}
	return raw
}

// Helper for debugging purposes and dump a full HTTP request
func debugHTTP(r *http.Request, debugCheck bool, showBody bool) string {
	var debug string
	if debugCheck {
		debug = fmt.Sprintf("%s\n", "---------------- request")
		requestDump, err := httputil.DumpRequest(r, showBody)
		if err != nil {
			log.Printf("error while dumprequest %v", err)
		}
		debug += fmt.Sprintf("%s\n", sanitizeHeaders(string(requestDump)))
		if !showBody {
			debug += fmt.Sprintf("---------------- hidden body (%d bytes)\n", len(requestDump))
		}
		debug += fmt.Sprintf("\n%s\n", "---------------- end")
	}
	return debug
}

// Helper to send HTTP response
func apiHTTPResponse(w http.ResponseWriter, cType string, code int, data interface{}) {
	if cType != "" {
		w.Header().Set(contentType, cType)
	}
	content, err := json.Marshal(data)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("error serializing response: %v", err)
		content = []byte("error serializing response")
	}
	log.Printf("HTTP %d", code)
	w.WriteHeader(code)
	_, _ = w.Write(content)
}

// Helper to handle API error responses
func apiErrorResponse(w http.ResponseWriter, msg string, code int, err error) {
	log.Printf("%s: %v", msg, err)
	apiHTTPResponse(w, JSONApplicationUTF8, code, ResponseMessage{Message: msg})
}

// Helper to check if the request comes from the list of allowed IPs
func verifyAllowedIP(ip string) bool {
	for _, i := range serviceConfig.AllowList {
		if i == ip {
			return true
		}
	}
	return false
}

// Helper to check if the request authorization token is valid
func verifyauthToken(token string) bool {
	if token == serviceConfig.AuthToken {
		return true
	}
	return false
}

// Wrapper/helper to handle IP address verification and authentication
func handlerAuthCheck(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for allowed IP addresses and Authorization Token
		if !verifyAllowedIP(r.Header.Get(realIPAddress)) {
			apiErrorResponse(w, "Unauthorized", http.StatusForbidden, fmt.Errorf("IP address not allowed"))
			return
		}
		if !verifyauthToken(r.Header.Get(authToken)) {
			apiErrorResponse(w, "Unauthorized", http.StatusForbidden, fmt.Errorf("Incorrect Authorization Token"))
			return
		}
		h.ServeHTTP(w, r)
	})
}

// Helper function to prepare HTTP requests to be sent
func prepareRequest(reqType, reqURL string, params io.Reader, headers map[string]string) (*http.Response, error) {
	u, err := url.Parse(reqURL)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %v", err)
	}
	client := &http.Client{}
	if u.Scheme == "https" {
		certPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("error loading x509 certificate pool: %v", err)
		}
		tlsCfg := &tls.Config{RootCAs: certPool}
		client.Transport = &http.Transport{TLSClientConfig: tlsCfg}
	}
	req, err := http.NewRequest(reqType, reqURL, params)
	if err != nil {
		return nil, err
	}
	// Set custom User-Agent
	req.Header.Set(userAgent, screenerUserAgent)
	// Prepare headers
	for key, value := range headers {
		req.Header.Add(key, value)
	}
	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Helper function to send a request and return the response raw
func rawRequest(reqType, reqURL string, params io.Reader, headers map[string]string) (int, []byte, error) {
	resp, err := prepareRequest(reqType, reqURL, params, headers)
	if err != nil {
		return 0, nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Failed to close body %v", err)
		}
	}()
	// Read response
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, bodyBytes, nil
}

// Helper function to send a request and return the response raw
func parsedRequest(reqType, reqURL string, params io.Reader, headers map[string]string) (int, interface{}, error) {
	resp, err := prepareRequest(reqType, reqURL, params, headers)
	if err != nil {
		return 0, nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Failed to close body %v", err)
		}
	}()
	// Parse response
	var parsed interface{}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return 0, nil, fmt.Errorf("error parsing POST body %v", err)
	}
	return resp.StatusCode, parsed, nil
}
