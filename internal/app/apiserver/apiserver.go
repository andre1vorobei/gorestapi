package apiserver

import (
	"encoding/json"
	"fmt"
	"gorestapi/internal/app/model"
	"gorestapi/internal/app/store"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

var jwtSecretKey = []byte(os.Getenv("JWTSKEY"))

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
	if err := s.configureLogger(); err != nil {
		return err
	}

	if err := s.configureStore(); err != nil {
		return err
	}

	s.configureRouter()

	headersOK := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"})
	originsOK := handlers.AllowedOrigins([]string{"*"})
	methodsOK := handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "OPTION"})

	s.logger.Info("starting api server")

	return http.ListenAndServe(s.config.BindAddr, handlers.CORS(headersOK, originsOK, methodsOK)(s.router))
}

func (s *APIServer) configureRouter() {
	s.router.HandleFunc("/hello", s.handlerHello())
	s.router.HandleFunc("/register", s.apiRegister()).Methods("POST")
	s.router.HandleFunc("/login", s.apiLogin()).Methods("POST")
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

func (s *APIServer) apiLogin() http.HandlerFunc {
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

		_, errEm := s.store.User().FindByEmail(reqUser.Email)

		_, errUs := s.store.User().FindByUsername(reqUser.UserName)

		if errEm != nil && errUs != nil {
			s.apiRegister_result(w, r, "DEBUG", http.StatusNotFound)
			return
		}

		// TODO: перенести логику авторизации в отдельный модуль
		payload := jwt.MapClaims{
			"sub": reqUser.Email,
			"exp": time.Now().Add(time.Hour * 168).Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)

		signedToken, err := token.SignedString(jwtSecretKey)

		logResp := `{"access_token": %s}`
		logResp = fmt.Sprintf(logResp, signedToken)

		fmt.Println(string(jwtSecretKey))

		w.Header().Set("Content-Type", "application/json")

		s.apiRegister_result(w, r, "DEBUG", http.StatusOK)
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

		s.apiRegister_result(w, r, "DEBUG", http.StatusCreated)
	}
}
