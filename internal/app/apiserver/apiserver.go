package apiserver

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"gorestapi/internal/app/model"
	"gorestapi/internal/app/store"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecretKey = []byte(os.Getenv("JWTSKEY"))

var caCert *x509.CertPool
var ownCert tls.Certificate

type APIServer struct {
	config *Config
	logger *logrus.Logger
	router *mux.Router
	store  *store.Store
}

func New(conf *Config) *APIServer {
	return &APIServer{
		config: conf,
		logger: logrus.New(),
		router: mux.NewRouter(),
	}
}

func (s *APIServer) configureLogger() error {
	level, err := logrus.ParseLevel(s.config.LogLevel)
	if err != nil {
		return err
	}

	s.logger.SetLevel(level)

	return nil
}

func (s *APIServer) Start() error {
	readCert, err := os.ReadFile("certs/ca.crt")
	if err != nil {
		return err
	}

	caCert = x509.NewCertPool()
	caCert.AppendCertsFromPEM(readCert)

	ownCert, err = tls.LoadX509KeyPair("certs/auth.crt", "certs/auth.key")
	if err != nil {
		return err
	}

	if err := s.configureLogger(); err != nil {
		return err
	}

	if err := s.configureStore(); err != nil {
		return err
	}

	s.configureRouter()

	corsMiddleware := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
		MaxAge:           86400,
	})

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		//RootCAs:      caCert,
		//Certificates: []tls.Certificate{ownCert},
	}

	server := &http.Server{
		Addr:      s.config.BindAddr,
		Handler:   corsMiddleware.Handler(s.router),
		TLSConfig: tlsConfig,
	}

	s.logger.Info("starting api server")

	return server.ListenAndServeTLS("certs/auth.crt", "certs/auth.key")
}

func (s *APIServer) configureRouter() {
	s.router.HandleFunc("/hello", s.handlerHello())
	s.router.HandleFunc("/api/auth/register", s.apiRegister()).Methods("POST")
	s.router.HandleFunc("/api/auth/login", s.apiLogin()).Methods("POST")
}

func (s *APIServer) configureStore() error {
	st := store.New(s.config.Store)
	if err := st.Open(); err != nil {
		return err
	}
	s.store = st

	return nil
}

func (s *APIServer) handlerHello() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "Hello niger")
	}
}

func (s *APIServer) apiRegister_result(resp http.ResponseWriter, req *http.Request, loglevel string, res int) {
	resLog := fmt.Sprintf("Reg request [%s]: %s - %d", req.RemoteAddr, req.Method, res)
	switch loglevel {
	case "INFO":
		s.logger.Info(resLog)
	case "DEBUG":
		s.logger.Debug(resLog)
	case "WARNING":
		s.logger.Warn(resLog)
	}
	resp.WriteHeader(res)
}

func (s *APIServer) apiLogin_result(resp http.ResponseWriter, req *http.Request, loglevel string, res int) {
	resLog := fmt.Sprintf("Login request [%s]: %s - %d", req.RemoteAddr, req.Method, res)
	switch loglevel {
	case "INFO":
		s.logger.Info(resLog)
	case "DEBUG":
		s.logger.Debug(resLog)
	case "WARNING":
		s.logger.Warn(resLog)
	}
	resp.WriteHeader(res)
}

func (s *APIServer) apiLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		if r.Body == nil {
			s.apiLogin_result(w, r, "DEBUG", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		data, err := io.ReadAll(r.Body)
		if err != nil {
			s.apiLogin_result(w, r, "DEBUG", http.StatusUnprocessableEntity)
			return
		}

		reqUser := &model.User{}

		if err = json.Unmarshal(data, reqUser); err != nil {
			s.apiLogin_result(w, r, "DEBUG", http.StatusBadRequest)
			return
		}

		if reqUser.Email == "" && reqUser.UserName == "" {
			s.apiLogin_result(w, r, "DEBUG", http.StatusBadRequest)
			return
		}

		if err = reqUser.Validate(); err != nil {
			s.apiLogin_result(w, r, "DEBUG", http.StatusBadRequest)
			return
		}

		findedUser := &model.User{}

		if reqUser.Email != "" {
			findedUser, _ = s.store.User().FindByEmail(reqUser.Email)
		} else if reqUser.UserName != "" {
			findedUser, _ = s.store.User().FindByUsername(reqUser.UserName)
		} else {
			s.apiLogin_result(w, r, "DEBUG", http.StatusNotFound)
			return
		}

		if findedUser == nil {
			s.apiLogin_result(w, r, "DEBUG", http.StatusNotFound)
			return
		}

		if err = bcrypt.CompareHashAndPassword([]byte(findedUser.EncryptedPassword), []byte(reqUser.Password)); err != nil {
			s.apiLogin_result(w, r, "DEBUG", http.StatusBadRequest)
			return
		}

		// TODO: перенести логику авторизации в отдельный модуль
		payload := jwt.MapClaims{
			"sub": findedUser.ID,
			"exp": time.Now().Add(time.Hour * 168).Unix(),

			"userEmail": reqUser.Email,
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)

		signedToken, err := token.SignedString(jwtSecretKey)

		logResp := `{"access_token": "%s"}`
		logResp = fmt.Sprintf(logResp, signedToken)

		fmt.Println(string(jwtSecretKey))

		w.Header().Set("Content-Type", "application/json")

		s.apiLogin_result(w, r, "DEBUG", http.StatusOK)
		w.Write([]byte(logResp))
	}
}

func (s *APIServer) apiRegister() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		if r.Body == nil {
			s.apiRegister_result(w, r, "DEBUG", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		data, err := io.ReadAll(r.Body)
		if err != nil {
			s.apiRegister_result(w, r, "DEBUG", http.StatusUnprocessableEntity)
			return
		}

		reqUser := &model.User{}

		if err = json.Unmarshal(data, reqUser); err != nil {
			s.apiRegister_result(w, r, "DEBUG", http.StatusBadRequest)
			return
		}

		if err = reqUser.Validate(); err != nil {
			s.apiRegister_result(w, r, "DEBUG", http.StatusBadRequest)
			return
		}

		_, err = s.store.User().Create(reqUser)
		if err != nil {
			s.apiRegister_result(w, r, "DEBUG", http.StatusConflict)
			return
		}
		//TODO: КОСТЫЛЬ!!!!
		requestBody, _ := json.Marshal(map[string]interface{}{
			"userid":         reqUser.ID,
			"username":       reqUser.UserName,
			"description":    "BlaBlaBla default description",
			"avatarurl":      "/default.jpg",
			"birthday":       "2000-01-01",
			"followerscount": 0,
		})

		req, err := http.NewRequest(
			"POST",
			"https://127.0.0.1:8081/api/profiles/crprofile",
			bytes.NewBuffer(requestBody),
		)
		if err != nil {
			s.apiRegister_result(w, r, "DEBUG", http.StatusInternalServerError)
			return
		}

		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: caCert,
					//Certificates: []tls.Certificate{ownCert},
					//MinVersion: tls.VersionTLS12,
				},
			},
		}

		resp, err := client.Do(req)
		if err != nil {
			s.apiRegister_result(w, r, "DEBUG", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		fmt.Println(resp.StatusCode)

		s.apiRegister_result(w, r, "DEBUG", http.StatusCreated)
	}
}
