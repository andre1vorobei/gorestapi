package store

type Config struct {
	Databaseurl string `toml:"database_url"`
}

func NewConfig() *Config {
	return &Config{}
}
