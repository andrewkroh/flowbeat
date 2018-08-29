package beater

type Config struct {
	NetflowAddr       string `config:"netflow.address"`
	NetflowReadBuffer uint32 `config:"netflow.read_buffer"`
}

var defaultConfig = Config{
	NetflowAddr:       ":2055",
	NetflowReadBuffer: 2 << 16,
}
