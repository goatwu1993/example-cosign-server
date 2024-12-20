package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	DEFAULT_LISTEN_ADDRESS = "localhost:8000"
)

var privateKey *rsa.PrivateKey

//var ecdsaPrivateKey *ecdsa.PrivateKey

type Server struct {
	logger *log.Logger
}

func loadPrivateKey(filename string, logger *log.Logger) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(filename)
	ok := false
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %v", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return privateKey, nil
	}
	logger.Infof("Failed to parse private key as PKCS1: %s. Trying to parse as PKCS8 Instead", err)
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}
	privateKey, ok = privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}
	return privateKey, nil
}

func jwtStrToCliam(jwtStr string) (map[string]interface{}, error) {
	jwtStr = strings.TrimPrefix(jwtStr, "Bearer ")
	claimBase64 := strings.Split(jwtStr, ".")[1]
	switch len(claimBase64) % 4 {
	case 2:
		claimBase64 += "=="
	case 3:
		claimBase64 += "="
	}
	// Decode the base64 string to ASCII text
	decodedClaim, err := base64.StdEncoding.DecodeString(claimBase64)
	if err != nil {
		return nil, fmt.Errorf("error decoding base64 data: %w", err)
	}
	jwtClaim := map[string]interface{}{}
	err = json.Unmarshal([]byte(decodedClaim), &jwtClaim)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling jwt claim: %w", err)
	}
	return jwtClaim, nil
}

func (s *Server) signData(
	data RequestData,
	validated_jwt_claim map[string]interface{},
) (string, error) {
	payload, err := base64.StdEncoding.DecodeString(data.Payload)
	if err != nil {
		return "", fmt.Errorf("error decoding base64 data: %w", err)
	}
	hasher := sha256.New()
	hasher.Write(payload)
	payloadHash := hasher.Sum(nil)
	payloadJson := map[string]interface{}{}
	err = json.Unmarshal(payload, &payloadJson)
	if err != nil {
		return "", fmt.Errorf("error unmarshalling payload: %w", err)
	}
	// TODO: maybe 403
	err = s.checkPermission(validated_jwt_claim, payloadJson)
	if err != nil {
		return "", fmt.Errorf("unauthorizated to sign payload: %w", err)
	}
	// TODO: use kms or hsm to sign the data
	signature, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, payloadHash)
	if err != nil {
		return "", fmt.Errorf("error signing data: %w", err)
	}
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)
	s.logger.Infof("signatureBase64: %s", signatureBase64)
	s.logger.Infof("validated_jwt_claim: %s", validated_jwt_claim)
	s.logger.Infof("payloadHash: %s", hex.EncodeToString(payloadHash))
	s.logger.Infof("payloadData: %s", payloadJson)
	s.logger.Infof("signature: %s", signatureBase64)
	return signatureBase64, nil

}

func (s *Server) checkPermission(
	claim map[string]interface{},
	payloadJson map[string]interface{},
) error {
	// Example 1: Check in program
	//   annotation, ok := payloadJson["optional"].(map[string]interface{})
	//   if !ok {
	//       return fmt.Errorf("optional field is not a map")
	//   }
	//   // must have a signer field
	//   signer, ok := annotation["signer"]
	//   if !ok {
	//       return fmt.Errorf("signer field not found")
	//   }
	//   signerStr, ok := signer.(string)
	//   if !ok {
	//       return fmt.Errorf("signer field is not a string")
	//   }
	//   if signerStr != "my-custom-kms" {
	//       return fmt.Errorf("signer is not my-custom-kms")
	//   }
	// Example 2: Check in OPA
	//   type OpaInput struct {
	//       ValidatedJwtClaim map[string]interface{} `json:"validated_jwt_claim"`
	//       Payload           map[string]interface{} `json:"payload"`
	//   }
	//   type OpaRequest struct {
	//       Input OpaInput `json:"input"`
	//   }
	//   opaReq := OpaRequest{
	//       Input: OpaInput{
	//           ValidatedJwtClaim: validated_jwt_claim,
	//           Payload:           payloadJson,
	//       },
	//   }
	//   client := &http.Client{}
	//   opaReqBytes, err := json.Marshal(opaReq)
	//   if err != nil {
	//       return fmt.Errorf("error marshalling opa request: %w", err)
	//   }
	//   req, err := http.NewRequest("POST", "http://localhost:8181/v1/data/signer", bytes.NewBuffer(opaReqBytes))
	//   if err != nil {
	//       return fmt.Errorf("error creating request: %w", err)
	//   }
	//   req.Header.Set("Content-Type", "application/json")
	//   resp, err := client.Do(req)
	//   if err != nil {
	//       return fmt.Errorf("error sending request: %w", err)
	//   }
	//   defer resp.Body.Close()
	//   if resp.StatusCode != http.StatusOK {
	//       return fmt.Errorf("opa request failed: %s", resp.Status)
	//   }
	s.logger.Infof("Claim %s is allowed to sign payload %s", claim, payloadJson)
	return nil
}

type RequestData struct {
	//Algorithm string `json:"algorithm"`
	Payload string `json:"payload"`
}

func (s *Server) signHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	// get Authorization header // remove Bearer if present
	jwtStr := r.Header.Get("Authorization")
	if jwtStr == "" {
		s.logger.Errorf("No Authorization header")
		http.Error(
			w,
			"{\"error\": \"No Authorization header\"}",
			http.StatusBadRequest,
		)
		return
	}
	jwtClaim, err := jwtStrToCliam(jwtStr)
	if err != nil {
		s.logger.Errorf("Error parsing jwt claim: %s", err)
		http.Error(
			w,
			fmt.Sprintf("{\"error\": \"%s\"}", strings.ReplaceAll(err.Error(), "\"", "'")),
			http.StatusBadRequest,
		)
		return
	}
	var requestData RequestData
	err = json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		s.logger.Errorf("Error parsing JSON: %s", err)
		http.Error(
			w,
			"{\"error\": \"invalid JSON\"}",
			http.StatusBadRequest,
		)
		return
	}
	// base64 decode the payload
	signatureBase64, err := s.signData(requestData, jwtClaim)
	if err != nil {
		s.logger.Errorf("Error signing data: %s", err)
		http.Error(
			w,
			fmt.Sprintf("{\"error\": \"%s\"}", strings.ReplaceAll(err.Error(), "\"", "'")),
			http.StatusBadRequest,
		)
		return
	}
	// Set Content-Type header
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write([]byte("{\"signature\":\"" + signatureBase64 + "\"}"))
	if err != nil {
		s.logger.Errorf("Error writing response: %s", err)
	}
}

func main() {
	logger := log.New()
	logger.SetLevel(log.InfoLevel)
	privateKeyData, err := os.ReadFile("./priv/private_key.pem")
	if err != nil {
		logger.Fatalf("Error reading private key: %s", err.Error())
		return
	}
	block, _ := pem.Decode(privateKeyData)
	if block == nil || (block.Type != "PRIVATE KEY" && block.Type != "RSA PRIVATE KEY") {
		logger.Fatal("Failed to decode PEM block containing private key")
		return
	}
	// TODO: use kms or hsm to sign the data
	privateKey, err = loadPrivateKey("./priv/private_key.pem", logger)
	if err != nil {
		logger.Errorf("Error parsing private key: %s", err)
		log.Fatal("Error parsing private key: ", err)
	}
	publicKey := privateKey.Public()
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		logger.Fatalf("Error marshalling public key: %s", err)
		return
	}
	publicKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	logger.Infof("Public key: \n%s", string(publicKeyPem))

	s := &Server{
		logger: logger,
		// TODO: set up opa
		// TODO: set up signer/kms/hsm
		// TODO: set up fluentbit
	}
	// Set up HTTP handler
	http.HandleFunc("/api/v1/sign", s.signHandler)
	http.HandleFunc("/api/v1/publicKey", func(w http.ResponseWriter, r *http.Request) {
		// x509
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, err := w.Write(publicKeyPem)
		if err != nil {
			logger.Infof("Error writing public key: %s", fmt.Errorf("error writing public key: %w", err))
		}
	})
	listenAddress := os.Getenv("MY_COSIGN_SERVER_LISTEN_ADDRESS")
	if listenAddress == "" {
		logger.Infof("MY_COSIGN_SERVER_LISTEN_ADDRESS not set. Using default %s", DEFAULT_LISTEN_ADDRESS)
		listenAddress = DEFAULT_LISTEN_ADDRESS
	}
	logger.Infof("Listening on %s", listenAddress)
	err = http.ListenAndServe(listenAddress, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
