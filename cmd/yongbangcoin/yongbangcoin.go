package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"runtime/pprof"
	"sync"
	"syscall"
	"time"

	"github.com/hankgao/toolbox/src/skytb"
	"github.com/skycoin/skycoin/src/api/webrpc"
	"github.com/skycoin/skycoin/src/cipher"
	"github.com/skycoin/skycoin/src/coin"
	"github.com/skycoin/skycoin/src/daemon"
	"github.com/skycoin/skycoin/src/gui"
	"github.com/skycoin/skycoin/src/util/browser"
	"github.com/skycoin/skycoin/src/util/cert"
	"github.com/skycoin/skycoin/src/util/file"
	"github.com/skycoin/skycoin/src/util/logging"
	"github.com/skycoin/skycoin/src/visor"
	"github.com/skycoin/skycoin/src/wallet"
)

var (
	// Version of the node. Can be set by -ldflags
	Version = "0.23.0"
	// Commit ID. Can be set by -ldflags
	Commit = ""
	// Branch name. Can be set by -ldflags
	Branch = ""
	// ConfigMode (possible values are "", "STANDALONE_CLIENT").
	// This is used to change the default configuration.
	// Can be set by -ldflags
	ConfigMode = ""

	help = false

	logger = logging.MustGetLogger("main")

	// GenesisSignatureStr hex string of genesis signature
	GenesisSignatureStr = ""
	// GenesisAddressStr genesis address string
	GenesisAddressStr = "ieJZqy74rXk3h23MeofyK8tLyvapsnhySx"
	// BlockchainPubkeyStr pubic key string
	BlockchainPubkeyStr = "02177c07515f5f1e144948d21816ea1e90a7dfbace263f56e41dcbe9059d5cd0d5"
	// BlockchainSeckeyStr empty private key string
	BlockchainSeckeyStr = ""

	// GenesisTimestamp genesis block create unix time
	GenesisTimestamp uint64 = 1527499841
	// GenesisCoinVolume represents the coin capacity
	GenesisCoinVolume uint64 = 300e15

	// DefaultConnections the default trust node addresses
	DefaultConnections = []string{
		"74.120.168.216:7050",
		"74.120.174.69:7050",
	}
)

// Config records the node's configuration
type Config struct {
	// Disable peer exchange
	DisablePEX bool
	// Download peer list
	DownloadPeerList bool
	// Download the peers list from this URL
	PeerListURL string
	// Don't make any outgoing connections
	DisableOutgoingConnections bool
	// Don't allowing incoming connections
	DisableIncomingConnections bool
	// Disables networking altogether
	DisableNetworking bool
	// Disables wallet API
	EnableWalletAPI bool
	// Disable CSRF check in the wallet api
	DisableCSRF bool
	// Enable /wallet/seed api endpoint
	EnableSeedAPI bool

	// Only run on localhost and only connect to others on localhost
	LocalhostOnly bool
	// Which address to serve on. Leave blank to automatically assign to a
	// public interface
	Address string
	//gnet uses this for TCP incoming and outgoing
	Port int
	//max outgoing connections to maintain
	MaxOutgoingConnections int
	// How often to make outgoing connections
	OutgoingConnectionsRate time.Duration
	// PeerlistSize represents the maximum number of peers that the pex would maintain
	PeerlistSize int
	// Wallet Address Version
	//AddressVersion string
	// Remote web interface
	WebInterface      bool
	WebInterfacePort  int
	WebInterfaceAddr  string
	WebInterfaceCert  string
	WebInterfaceKey   string
	WebInterfaceHTTPS bool

	RPCInterface     bool
	RPCInterfacePort int
	RPCInterfaceAddr string

	// Launch System Default Browser after client startup
	LaunchBrowser bool

	// If true, print the configured client web interface address and exit
	PrintWebInterfaceAddress bool

	// Data directory holds app data -- defaults to ~/.yongbangcoin
	DataDirectory string
	// GUI directory contains assets for the html gui
	GUIDirectory string

	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	// Logging
	ColorLog bool
	// This is the value registered with flag, it is converted to LogLevel after parsing
	LogLevel string
	// Disable "Reply to ping", "Received pong" log messages
	DisablePingPong bool

	// Wallets
	// Defaults to ${DataDirectory}/wallets/
	WalletDirectory string
	// Wallet crypto type
	WalletCryptoType string

	RunMaster bool

	GenesisSignature cipher.Sig
	GenesisTimestamp uint64
	GenesisAddress   cipher.Address

	BlockchainPubkey cipher.PubKey
	BlockchainSeckey cipher.SecKey

	/* Developer options */

	// Enable cpu profiling
	ProfileCPU bool
	// Where the file is written to
	ProfileCPUFile string
	// HTTP profiling interface (see http://golang.org/pkg/net/http/pprof/)
	HTTPProf bool
	// Will force it to connect to this ip:port, instead of waiting for it
	// to show up as a peer
	ConnectTo string

	DBPath       string
	DBReadOnly   bool
	Arbitrating  bool
	RPCThreadNum uint // rpc number
	LogToFile    bool
}

func (c *Config) register() {
	flag.BoolVar(&help, "help", false, "Show help")
	flag.BoolVar(&c.DisablePEX, "disable-pex", c.DisablePEX, "disable PEX peer discovery")
	flag.BoolVar(&c.DownloadPeerList, "download-peerlist", c.DownloadPeerList, "download a peers.txt from -peerlist-url")
	flag.StringVar(&c.PeerListURL, "peerlist-url", c.PeerListURL, "with -download-peerlist=true, download a peers.txt file from this url")
	flag.BoolVar(&c.DisableOutgoingConnections, "disable-outgoing", c.DisableOutgoingConnections, "Don't make outgoing connections")
	flag.BoolVar(&c.DisableIncomingConnections, "disable-incoming", c.DisableIncomingConnections, "Don't make incoming connections")
	flag.BoolVar(&c.DisableNetworking, "disable-networking", c.DisableNetworking, "Disable all network activity")
	flag.BoolVar(&c.EnableWalletAPI, "enable-wallet-api", c.EnableWalletAPI, "Enable the wallet API")
	flag.BoolVar(&c.DisableCSRF, "disable-csrf", c.DisableCSRF, "disable csrf check")
	flag.BoolVar(&c.EnableSeedAPI, "enable-seed-api", c.EnableSeedAPI, "enable /wallet/seed api")
	flag.StringVar(&c.Address, "address", c.Address, "IP Address to run application on. Leave empty to default to a public interface")
	flag.IntVar(&c.Port, "port", c.Port, "Port to run application on")

	flag.BoolVar(&c.WebInterface, "web-interface", c.WebInterface, "enable the web interface")
	flag.IntVar(&c.WebInterfacePort, "web-interface-port", c.WebInterfacePort, "port to serve web interface on")
	flag.StringVar(&c.WebInterfaceAddr, "web-interface-addr", c.WebInterfaceAddr, "addr to serve web interface on")
	flag.StringVar(&c.WebInterfaceCert, "web-interface-cert", c.WebInterfaceCert, "cert.pem file for web interface HTTPS. If not provided, will use cert.pem in -data-directory")
	flag.StringVar(&c.WebInterfaceKey, "web-interface-key", c.WebInterfaceKey, "key.pem file for web interface HTTPS. If not provided, will use key.pem in -data-directory")
	flag.BoolVar(&c.WebInterfaceHTTPS, "web-interface-https", c.WebInterfaceHTTPS, "enable HTTPS for web interface")

	flag.BoolVar(&c.RPCInterface, "rpc-interface", c.RPCInterface, "enable the rpc interface")
	flag.IntVar(&c.RPCInterfacePort, "rpc-interface-port", c.RPCInterfacePort, "port to serve rpc interface on")
	flag.StringVar(&c.RPCInterfaceAddr, "rpc-interface-addr", c.RPCInterfaceAddr, "addr to serve rpc interface on")
	flag.UintVar(&c.RPCThreadNum, "rpc-thread-num", c.RPCThreadNum, "rpc thread number")

	flag.BoolVar(&c.LaunchBrowser, "launch-browser", c.LaunchBrowser, "launch system default webbrowser at client startup")
	flag.BoolVar(&c.PrintWebInterfaceAddress, "print-web-interface-address", c.PrintWebInterfaceAddress, "print configured web interface address and exit")
	flag.StringVar(&c.DataDirectory, "data-dir", c.DataDirectory, "directory to store app data (defaults to ~/.yongbangcoin)")
	flag.StringVar(&c.DBPath, "db-path", c.DBPath, "path of database file (defaults to ~/.yongbangcoin/data.db)")
	flag.BoolVar(&c.DBReadOnly, "db-read-only", c.DBReadOnly, "open bolt db read-only")
	flag.StringVar(&c.ConnectTo, "connect-to", c.ConnectTo, "connect to this ip only")
	flag.BoolVar(&c.ProfileCPU, "profile-cpu", c.ProfileCPU, "enable cpu profiling")
	flag.StringVar(&c.ProfileCPUFile, "profile-cpu-file", c.ProfileCPUFile, "where to write the cpu profile file")
	flag.BoolVar(&c.HTTPProf, "http-prof", c.HTTPProf, "Run the http profiling interface")
	flag.StringVar(&c.LogLevel, "log-level", c.LogLevel, "Choices are: debug, info, warn, error, fatal, panic")
	flag.BoolVar(&c.ColorLog, "color-log", c.ColorLog, "Add terminal colors to log output")
	flag.BoolVar(&c.DisablePingPong, "no-ping-log", c.DisablePingPong, `disable "reply to ping" and "received pong" debug log messages`)
	flag.BoolVar(&c.LogToFile, "logtofile", c.LogToFile, "log to file")
	flag.StringVar(&c.GUIDirectory, "gui-dir", c.GUIDirectory, "static content directory for the html gui")

	// Key Configuration Data
	flag.BoolVar(&c.RunMaster, "master", c.RunMaster, "run the daemon as blockchain master server")

	flag.StringVar(&BlockchainPubkeyStr, "master-public-key", BlockchainPubkeyStr, "public key of the master chain")
	flag.StringVar(&BlockchainSeckeyStr, "master-secret-key", BlockchainSeckeyStr, "secret key, set for master")

	flag.StringVar(&GenesisAddressStr, "genesis-address", GenesisAddressStr, "genesis address")
	flag.StringVar(&GenesisSignatureStr, "genesis-signature", GenesisSignatureStr, "genesis block signature")
	flag.Uint64Var(&c.GenesisTimestamp, "genesis-timestamp", c.GenesisTimestamp, "genesis block timestamp")

	flag.StringVar(&c.WalletDirectory, "wallet-dir", c.WalletDirectory, "location of the wallet files. Defaults to ~/.yongbangcoin/wallet/")
	flag.IntVar(&c.MaxOutgoingConnections, "max-outgoing-connections", c.MaxOutgoingConnections, "The maximum outgoing connections allowed")
	flag.IntVar(&c.PeerlistSize, "peerlist-size", c.PeerlistSize, "The peer list size")
	flag.DurationVar(&c.OutgoingConnectionsRate, "connection-rate", c.OutgoingConnectionsRate, "How often to make an outgoing connection")
	flag.BoolVar(&c.LocalhostOnly, "localhost-only", c.LocalhostOnly, "Run on localhost and only connect to localhost peers")
	flag.BoolVar(&c.Arbitrating, "arbitrating", c.Arbitrating, "Run node in arbitrating mode")
	flag.StringVar(&c.WalletCryptoType, "wallet-crypto-type", c.WalletCryptoType, "wallet crypto type. Can be sha256-xor or scrypt-chacha20poly1305")
}

var home = file.UserHome()

var devConfig = Config{
	// Disable peer exchange
	DisablePEX: false,
	// Don't make any outgoing connections
	DisableOutgoingConnections: false,
	// Don't allowing incoming connections
	DisableIncomingConnections: false,
	// Disables networking altogether
	DisableNetworking: false,
	// Enable wallet API
	EnableWalletAPI: false,
	// Enable seed API
	EnableSeedAPI: false,
	// Disable CSRF check in the wallet api
	DisableCSRF: false,
	// Only run on localhost and only connect to others on localhost
	LocalhostOnly: false,
	// Which address to serve on. Leave blank to automatically assign to a
	// public interface
	Address: "",
	//gnet uses this for TCP incoming and outgoing
	Port: 7040,
	// MaxOutgoingConnections is the maximum outgoing connections allowed.
	MaxOutgoingConnections: 16,
	DownloadPeerList:       false,
	PeerListURL:            "https://downloads.yongbangcoin.net/blockchain/peers.txt",
	// How often to make outgoing connections, in seconds
	OutgoingConnectionsRate: time.Second * 5,
	PeerlistSize:            65535,
	// Wallet Address Version
	//AddressVersion: "test",
	// Remote web interface
	WebInterface:             true,
	WebInterfacePort:         7050,
	WebInterfaceAddr:         "127.0.0.1",
	WebInterfaceCert:         "",
	WebInterfaceKey:          "",
	WebInterfaceHTTPS:        false,
	PrintWebInterfaceAddress: false,

	RPCInterface:     true,
	RPCInterfacePort: 7060,
	RPCInterfaceAddr: "127.0.0.1",
	RPCThreadNum:     5,

	LaunchBrowser: false,
	// Data directory holds app data -- defaults to ~/.yongbangcoin
	DataDirectory: filepath.Join(home, ".yongbangcoin"),
	// Web GUI static resources
	GUIDirectory: "./src/gui/static/",
	// Logging
	ColorLog:        true,
	LogLevel:        "INFO",
	LogToFile:       false,
	DisablePingPong: false,

	// Wallets
	WalletDirectory:  "",
	WalletCryptoType: string(wallet.CryptoTypeScryptChacha20poly1305),

	// Timeout settings for http.Server
	// https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/
	ReadTimeout:  10 * time.Second,
	WriteTimeout: 60 * time.Second,
	IdleTimeout:  120 * time.Second,

	// Centralized network configuration
	RunMaster:        false,
	BlockchainPubkey: cipher.PubKey{},
	BlockchainSeckey: cipher.SecKey{},

	GenesisAddress:   cipher.Address{},
	GenesisTimestamp: GenesisTimestamp,
	GenesisSignature: cipher.Sig{},

	/* Developer options */

	// Enable cpu profiling
	ProfileCPU: false,
	// Where the file is written to
	ProfileCPUFile: "skycoin.prof",
	// HTTP profiling interface (see http://golang.org/pkg/net/http/pprof/)
	HTTPProf: false,
	// Will force it to connect to this ip:port, instead of waiting for it
	// to show up as a peer
	ConnectTo: "",
}

func init() {
	applyConfigMode()
}

func applyConfigMode() {
	switch ConfigMode {
	case "":
	case "STANDALONE_CLIENT":
		devConfig.EnableWalletAPI = true
		devConfig.EnableSeedAPI = true
		devConfig.LaunchBrowser = true
		devConfig.DisableCSRF = false
		devConfig.DownloadPeerList = true
		devConfig.RPCInterface = false
		devConfig.WebInterface = true
		devConfig.LogToFile = false
		devConfig.ColorLog = true
	default:
		panic("Invalid ConfigMode")
	}
}

// Parse prepare the config
func (c *Config) Parse() {
	c.register()
	flag.Parse()
	if help {
		flag.Usage()
		os.Exit(0)
	}
	c.postProcess()
}

func (c *Config) postProcess() {
	var err error
	if GenesisSignatureStr != "" {
		c.GenesisSignature, err = cipher.SigFromHex(GenesisSignatureStr)
		panicIfError(err, "Invalid Signature")
	}
	if GenesisAddressStr != "" {
		c.GenesisAddress, err = cipher.DecodeBase58Address(GenesisAddressStr)
		panicIfError(err, "Invalid Address")
	}
	if BlockchainPubkeyStr != "" {
		c.BlockchainPubkey, err = cipher.PubKeyFromHex(BlockchainPubkeyStr)
		panicIfError(err, "Invalid Pubkey")
	}
	if BlockchainSeckeyStr != "" {
		c.BlockchainSeckey, err = cipher.SecKeyFromHex(BlockchainSeckeyStr)
		panicIfError(err, "Invalid Seckey")
		BlockchainSeckeyStr = ""
	}
	if BlockchainSeckeyStr != "" {
		c.BlockchainSeckey = cipher.SecKey{}
	}

	c.DataDirectory, err = file.InitDataDir(c.DataDirectory)
	panicIfError(err, "Invalid DataDirectory")

	if c.WebInterfaceCert == "" {
		c.WebInterfaceCert = filepath.Join(c.DataDirectory, "cert.pem")
	}
	if c.WebInterfaceKey == "" {
		c.WebInterfaceKey = filepath.Join(c.DataDirectory, "key.pem")
	}

	if c.WalletDirectory == "" {
		c.WalletDirectory = filepath.Join(c.DataDirectory, "wallets")
	}

	if c.DBPath == "" {
		c.DBPath = filepath.Join(c.DataDirectory, "data.db")
	}

	if c.RunMaster {
		// Run in arbitrating mode if the node is master
		c.Arbitrating = true
	}

	// Don't open browser to load wallets if wallet apis are disabled.
	if c.EnableWalletAPI {
		c.GUIDirectory = file.ResolveResourceDirectory(c.GUIDirectory)
	} else {
		c.LaunchBrowser = false
	}
}

func panicIfError(err error, msg string, args ...interface{}) {
	if err != nil {
		log.Panicf(msg+": %v", append(args, err)...)
	}
}

func printProgramStatus() {
	p := pprof.Lookup("goroutine")
	if err := p.WriteTo(os.Stdout, 2); err != nil {
		fmt.Println("ERROR:", err)
		return
	}
}

// Catches SIGUSR1 and prints internal program state
func catchDebug() {
	sigchan := make(chan os.Signal, 1)
	//signal.Notify(sigchan, syscall.SIGUSR1)
	signal.Notify(sigchan, syscall.Signal(0xa)) // SIGUSR1 = Signal(0xa)
	for {
		select {
		case <-sigchan:
			printProgramStatus()
		}
	}
}

func catchInterrupt(quit chan<- struct{}) {
	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt)
	<-sigchan
	signal.Stop(sigchan)
	close(quit)

	// If ctrl-c is called again, panic so that the program state can be examined.
	// Ctrl-c would be called again if program shutdown was stuck.
	go catchInterruptPanic()
}

// catchInterruptPanic catches os.Interrupt and panics
func catchInterruptPanic() {
	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt)
	<-sigchan
	signal.Stop(sigchan)
	printProgramStatus()
	panic("SIGINT")
}

func createGUI(c *Config, d *daemon.Daemon, host string, quit chan struct{}) (*gui.Server, error) {
	var s *gui.Server
	var err error

	config := gui.Config{
		StaticDir:       c.GUIDirectory,
		DisableCSRF:     c.DisableCSRF,
		EnableWalletAPI: c.EnableWalletAPI,
		ReadTimeout:     c.ReadTimeout,
		WriteTimeout:    c.WriteTimeout,
		IdleTimeout:     c.IdleTimeout,
	}

	if c.WebInterfaceHTTPS {
		// Verify cert/key parameters, and if neither exist, create them
		if err := cert.CreateCertIfNotExists(host, c.WebInterfaceCert, c.WebInterfaceKey, "Skycoind"); err != nil {
			logger.Errorf("gui.CreateCertIfNotExists failure: %v", err)
			return nil, err
		}

		s, err = gui.CreateHTTPS(host, config, d, c.WebInterfaceCert, c.WebInterfaceKey)
	} else {
		s, err = gui.Create(host, config, d)
	}
	if err != nil {
		logger.Errorf("Failed to start web GUI: %v", err)
		return nil, err
	}

	return s, nil
}

func initLogFile(dataDir string) (*os.File, error) {
	logDir := filepath.Join(dataDir, "logs")
	if err := createDirIfNotExist(logDir); err != nil {
		logger.Errorf("createDirIfNotExist(%s) failed: %v", logDir, err)
		return nil, fmt.Errorf("createDirIfNotExist(%s) failed: %v", logDir, err)
	}

	// open log file
	tf := "2006-01-02-030405"
	logfile := filepath.Join(logDir, fmt.Sprintf("%s-v%s.log", time.Now().Format(tf), Version))

	f, err := os.OpenFile(logfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		logger.Errorf("os.OpenFile(%s) failed: %v", logfile, err)
		return nil, err
	}

	hook := logging.NewWriteHook(f)
	logging.AddHook(hook)

	return f, nil
}

func initProfiling(httpProf, profileCPU bool, profileCPUFile string) {
	if profileCPU {
		f, err := os.Create(profileCPUFile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}
	if httpProf {
		go func() {
			log.Println(http.ListenAndServe("localhost:6060", nil))
		}()
	}
}

func configureDaemon(c *Config) daemon.Config {
	//cipher.SetAddressVersion(c.AddressVersion)
	dc := daemon.NewConfig()
	dc.Pex.DataDirectory = c.DataDirectory
	dc.Pex.Disabled = c.DisablePEX
	dc.Pex.Max = c.PeerlistSize
	dc.Pex.DownloadPeerList = c.DownloadPeerList
	dc.Pex.PeerListURL = c.PeerListURL
	dc.Daemon.DisableOutgoingConnections = c.DisableOutgoingConnections
	dc.Daemon.DisableIncomingConnections = c.DisableIncomingConnections
	dc.Daemon.DisableNetworking = c.DisableNetworking
	dc.Daemon.Port = c.Port
	dc.Daemon.Address = c.Address
	dc.Daemon.LocalhostOnly = c.LocalhostOnly
	dc.Daemon.OutgoingMax = c.MaxOutgoingConnections
	dc.Daemon.DataDirectory = c.DataDirectory
	dc.Daemon.LogPings = !c.DisablePingPong

	if c.OutgoingConnectionsRate == 0 {
		c.OutgoingConnectionsRate = time.Millisecond
	}
	dc.Daemon.OutgoingRate = c.OutgoingConnectionsRate
	dc.Visor.Config.IsMaster = c.RunMaster

	dc.Visor.Config.BlockchainPubkey = c.BlockchainPubkey
	dc.Visor.Config.BlockchainSeckey = c.BlockchainSeckey

	dc.Visor.Config.GenesisAddress = c.GenesisAddress
	dc.Visor.Config.GenesisSignature = c.GenesisSignature
	dc.Visor.Config.GenesisTimestamp = c.GenesisTimestamp
	dc.Visor.Config.GenesisCoinVolume = GenesisCoinVolume
	dc.Visor.Config.DBPath = c.DBPath
	dc.Visor.Config.DBReadOnly = c.DBReadOnly
	dc.Visor.Config.Arbitrating = c.Arbitrating
	dc.Visor.Config.EnableWalletAPI = c.EnableWalletAPI
	dc.Visor.Config.WalletDirectory = c.WalletDirectory
	dc.Visor.Config.BuildInfo = visor.BuildInfo{
		Version: Version,
		Commit:  Commit,
		Branch:  Branch,
	}
	dc.Visor.Config.EnableSeedAPI = c.EnableSeedAPI

	dc.Gateway.EnableWalletAPI = c.EnableWalletAPI

	// Initialize wallet default crypto type
	cryptoType, err := wallet.CryptoTypeFromString(c.WalletCryptoType)
	if err != nil {
		log.Panic(err)
	}

	dc.Visor.Config.WalletCryptoType = cryptoType

	return dc
}

// Run starts the skycoin node
func Run(c *Config) {
	defer func() {
		// try catch panic in main thread
		if r := recover(); r != nil {
			logger.Errorf("recover: %v\nstack:%v", r, string(debug.Stack()))
		}
	}()

	logLevel, err := logging.LevelFromString(c.LogLevel)
	if err != nil {
		logger.Error("Invalid -log-level:", err)
		return
	}

	logging.SetLevel(logLevel)

	if c.ColorLog {
		logging.EnableColors()
	} else {
		logging.DisableColors()
	}

	var logFile *os.File
	if c.LogToFile {
		var err error
		logFile, err = initLogFile(c.DataDirectory)
		if err != nil {
			logger.Error(err)
			return
		}
	}

	scheme := "http"
	if c.WebInterfaceHTTPS {
		scheme = "https"
	}
	host := fmt.Sprintf("%s:%d", c.WebInterfaceAddr, c.WebInterfacePort)
	fullAddress := fmt.Sprintf("%s://%s", scheme, host)
	logger.Critical().Infof("Full address: %s", fullAddress)
	if c.PrintWebInterfaceAddress {
		fmt.Println(fullAddress)
	}

	initProfiling(c.HTTPProf, c.ProfileCPU, c.ProfileCPUFile)

	var wg sync.WaitGroup

	// If the user Ctrl-C's, shutdown properly
	quit := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		catchInterrupt(quit)
	}()

	// Watch for SIGUSR1
	wg.Add(1)
	func() {
		defer wg.Done()
		go catchDebug()
	}()

	// creates blockchain instance
	dconf := configureDaemon(c)

	logger.Infof("Opening database %s", dconf.Visor.Config.DBPath)
	db, err := visor.OpenDB(dconf.Visor.Config.DBPath, dconf.Visor.Config.DBReadOnly)
	if err != nil {
		logger.Errorf("Database failed to open: %v. Is another skycoin instance running?", err)
		return
	}

	d, err := daemon.NewDaemon(dconf, db, DefaultConnections)
	if err != nil {
		logger.Error(err)
		return
	}

	var rpc *webrpc.WebRPC
	if c.RPCInterface {
		rpcAddr := fmt.Sprintf("%v:%v", c.RPCInterfaceAddr, c.RPCInterfacePort)
		rpc, err = webrpc.New(rpcAddr, webrpc.Config{
			ReadTimeout:  c.ReadTimeout,
			WriteTimeout: c.WriteTimeout,
			IdleTimeout:  c.IdleTimeout,
			ChanBuffSize: 1000,
			WorkerNum:    c.RPCThreadNum,
		}, d.Gateway)
		if err != nil {
			logger.Error(err)
			return
		}
		rpc.ChanBuffSize = 1000
		rpc.WorkerNum = c.RPCThreadNum
	}

	var webInterface *gui.Server
	if c.WebInterface {
		webInterface, err = createGUI(c, d, host, quit)
		if err != nil {
			logger.Error(err)
			return
		}
	}

	// Debug only - forces connection on start.  Violates thread safety.
	if c.ConnectTo != "" {
		if err := d.Pool.Pool.Connect(c.ConnectTo); err != nil {
			logger.Errorf("Force connect %s failed, %v", c.ConnectTo, err)
			return
		}
	}

	errC := make(chan error, 10)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := d.Run(); err != nil {
			logger.Error(err)
			errC <- err
		}
	}()

	// start the webrpc
	if c.RPCInterface {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := rpc.Run(); err != nil {
				logger.Error(err)
				errC <- err
			}
		}()
	}

	if c.WebInterface {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := webInterface.Serve(); err != nil {
				logger.Error(err)
				errC <- err
			}
		}()

		if c.LaunchBrowser {
			wg.Add(1)
			go func() {
				defer wg.Done()

				// Wait a moment just to make sure the http interface is up
				time.Sleep(time.Millisecond * 100)

				logger.Infof("Launching System Browser with %s", fullAddress)
				if err := browser.Open(fullAddress); err != nil {
					logger.Error(err)
					return
				}
			}()
		}
	}

	/*
	   time.Sleep(5)
	   tx := InitTransaction()
	   _ = tx
	   err, _ = d.Visor.Visor.InjectTransaction(tx)
	   if err != nil {
	       log.Panic(err)
	   }
	*/

	/*
	   //first transaction
	   if c.RunMaster == true {
	       go func() {
	           for d.Visor.Visor.Blockchain.Head().Seq() < 2 {
	               time.Sleep(5)
	               tx := InitTransaction()
	               err, _ := d.Visor.Visor.InjectTransaction(tx)
	               if err != nil {
	                   //log.Panic(err)
	               }
	           }
	       }()
	   }
	*/

	//first transaction
	if c.RunMaster == true {
		go func() {
			if d.Visor.HeadBkSeq() < 1 {
				time.Sleep(5)
				tx := skytb.DistributionTransaction(
					"7b879c8f76b275d210f65721f5ac133e2935fc5a67b869640ecf1cd7ed2aca4c",
					"f45ec6ec06a3c0d720c41f7c443b95e77957f2a5c384e0a1e223cb7b5163cd6c",
					[]string{
						"2BLh3WRnYE96qudzCJ8T5J4w3nrTfNa9S8v",
						"2fVAzrqSsBat468cGpxMcKDG2yKEqTEPRnQ",
						"2D99abyweCWWJtTme9iq3cwnSsjaEAMx993",
						"24frCY1t6dvbDQktJb4hjDfnofdnJSa5rWL",
						"Ayws8PTNFy77KxthytzLargMoQ3hQmawSF",
						"2W85G5Sp84NeovHeLiiCzWQ35nSU7g6eVoT",
						"mjZeKaCF6FRHbioMxGtVcKp1yij6DCrWP",
						"7XAsyMa9SouTEY5faCgRN2EvJ5DnbhFVYW",
						"2RJUmMbnaJWem5TziFbeaRq7Azmq9hNPrX6",
						"28VuLWevSCvgKQutWMwHnu5LEpNS6Y9g351",
						"2YSpPomeGHZEaPjED7xgJhsazPPKbB2ewf",
						"2EC9kc6WANqD1Gk679fZ4u7n2e6yjBQX7Zm",
						"2j23k73ZGYJFX4h4n2RQyP93vyTUKH7g4JN",
						"qdNg6TiX79L4dBWzttUwC8mQ5HNKpvrvWF",
						"2ShgbuXYJYeRiFmE7vtjoy6Tw5Da995AnTp",
						"26Z1DyqYUdJ1TpeK5TjS1CopvMr3ts3aBvu",
						"2Xpz3iTp7gxGZkfuvDto9dQ7CvZm7jihLHv",
						"bmdLGjQXvGwsy2iP4cWCAjbKJCJDVpUDqU",
						"x283tNs4h5R2hGN6mXoXE7NwCHDN2ncpjQ",
						"fdWf525cShp8uK8x9SeHZPxycFscxuaTDk",
						"xwVyLPrDYTG77SNKdAX52VvrmTVtwuTTup",
						"21uFhsm58XEUqEbhDxcWkeAhELDv21fH6S1",
						"FsyJpcFjx6io9hPWwM69snafBwFicr6FqE",
						"2MekC9vtXRNCPPjLHaDyYoSC5nKvuu4wxya",
						"qh1MscffN3WQg8pzpRhQ4e4JAajQWFaHvb",
						"2DaK3jocdXWkdHrsmyLyWegcZNn2Xs2Hnag",
						"2X4BKETY87KgJ2jWnust8uHADN1xQ95Nnku",
						"wY1wfgHwYMBRT8h48xTx4rxWHi5FYVVj3U",
						"2kS5siDeRDwsNnX89LVUWPJ2ha8MSQpXhn4",
						"JJjEb65fP8KubRXndj2WokmagafhoWiqvC",
						"RpwWy8GQFHKxvAtb1aLSqkfRWj14TQbze2",
						"2bXjsnXZ5dZUnQii54TEtt9EbxUc8K1GCxE",
						"fth4af7f1BLSCNmvFdAjWdyiz3EbsndbPW",
						"2AsJLqssqiCUhuDMFfoUN1NuZZjJcmx52G7",
						"QkvmhPe1bMJM5NBwzGKxSGTAEByenQ4Lww",
						"2e1tzf2LActo3denmpHWQnLs6U4t3wS6DW1",
						"2gWFB5WHoMCxsZeGVm6TW3WF67KZKji5LXU",
						"My3QjTuSACjH7bQAdoSpvZZmyzmF5ezSd1",
						"2KycmDGWu27Vy5644MMBQ41EvRPPoBYefio",
						"2TDt5xGVxsPxdrfTnPdGVRtHzti3KZ2a8BQ",
						"H56AguS1p5wu9StUz8DsFUUcxWctYx26iX",
						"dbc2jbVhxoN9ULZVTVLXzwhqiHg3JFUneb",
						"btDQ379D2uMa7ZEYbKShB8yzJLBwRg5AT1",
						"ZBPLVo2qiDW8P5w5RjGSA3hpGnwYnhCddc",
						"nPb2o5mH4kFwcUoXWyMCmam7rwfkh8yZGx",
						"HTbyVKps1hCNe4zzBh4DTgfAtFK1BZS5AU",
						"rvRVw33DX8Fdvw1vbUY8bb36XbpmHM3pRS",
						"8n7juHTmMjjC3PkSqfUpXvVR3BgL1yzGzF",
						"jN2d52oCPrmA9anrbLxHuPnthUrCQfc8C2",
						"Non1yKT7HuRNmz1XLkbmb6zwtsbmMbjg6T",
						"No7SMznbqjMQqP6VVnR78DmgzoqvJqaeDs",
						"2AMcuDVLRFpJX1MLgPwzQc7LZaad6tiDtaW",
						"23G6oJa7vBSP4kkPCcnYN4NiwBkT6RUbDF1",
						"PrLivvgWnePbbxFyPj759ttMUFCDSECASz",
						"4Mt7NBkFEmZETWb2xeYYTyYDM78xfUockH",
						"gifHtDiP7VfhRUjJ7qCr8Qgn7LspxujmHE",
						"2hH9aimGQQA4teMk3xY3yw4mQGqvco3bAph",
						"PncRG7eeVD8JYdYWG99vVVTRAchMdu2irh",
						"hjEgZp512RpkNbQhMh1x2KWacwGyMhRJ2X",
						"WvgUDPkavMptaes1PkGRwk5qrJW5JgFUJv",
						"2LoYeWopmK8wrSdbFBkV57YWrxKUeM6iPAt",
						"2R8eYQFSAF9EkLBw1iBdGxLRdZP3XJZeiQu",
						"T1tg8TV3SGcVVzeE5TujxGibzGYatnes8G",
						"2WGK25oSZrEstN68bJS1WhKQbqaNu3qJsLF",
						"21HRG9uZvVqQm9VdAVzRXikSTUJCSqJiiwz",
						"CxsZn3AwCkXnnC72KwZPSkbzsDsttQGfk2",
						"zMVXMvGc7mX553KRFvMJXmSnhaC4nTZon2",
						"2Yha56vLn9rt5eEVo5uDo7NtafA4hTzTsk2",
						"2FSGPTMiHQ57xYsvMR4jgM4MD8ytyY5fBru",
						"C2ZdZ8LkvHhKHZwoNd1zeVPjcs45TZGc7Z",
						"2T3paja3vGwppf8XgrgkR3dBkEgNh6VodzV",
						"2ZnfhF8tPcEiz69nnykfFwKaCktupLH8Lgz",
						"2XSidKjggphaMcwLzJUv74E9qeCwqL52d2w",
						"qws1vRFFJ5XaWfFLtaHfEGEFjN9CuCAU9i",
						"2iRZngdAyXuNW9iJBzdN8LEPfAduaC9fuk9",
						"jYVd1RAtgbLwTybgx3ks27tCf97CJ1YnAk",
						"2PJPKUsWcwJGnqouYEsLpydoKxuXiKs1HdX",
						"KCLBGdqju1YisRYmz2yaiCtLjZ2mT8FdKY",
						"2bYb2UZXDornW3ZVPui3zxGo8g9x5vhDQNf",
						"2A5rGsEem6rCt5QJtjFMz3Nrp5knPLU6xKX",
						"2DMN3JFbDjhFFybDUyDaL7VFmFaR1YD8Pwa",
						"2QdBBNe3kGfcWUVbPV6xPhrZzNYT53qU3SG",
						"2YzQtMAZa3vS6aYKeihNHZ2KQCCED2dq2Y7",
						"uXaANwCWPA1UpMd61TkUe1puCWVaJhkA7A",
						"K7ngEQSP69NXkfMsAuVM9nB3tRDabvdnki",
						"XJo7KSo3S5SmHXbMBLbCNXYHwAbQ3emMf4",
						"2TM1tKoSzZ8Ln5mqU1rhnn69Z6sLS1Y7jFE",
						"AanusJ36vrTpn4rMT24HsvFXcaSegfH4ns",
						"2JtgJREELaBE8u4frRZncQdZgWNQ4jK2tFr",
						"2Pwye1Z3qUCLcaoNw3rdzH53giEDafdTrxG",
						"nHqJFgczRNYiArUpTeePEcANAZdDrRHdTN",
						"2YREfp3YVvb9uyB3x2QJVgrRdEDy4G5tjwK",
						"iKsKcPUZFbgwuc3X8pD1ZWeGutosCE75L",
						"7TtqgnUx7sPWuC8mLWus1Zcq9k9hMt74Tv",
						"2cCRwRPHPCfwVpMceA5zfanJ4mLHh9ucTes",
						"27Ed7smx4KtDAvLBciFpzdz6PiSHhDuvioY",
						"2jA69KmLUy4ocGt6KAdRXknrPDihVVwHLWQ",
						"64ZwUx3Z2iT3LPKKAUpQ5YWZRm4MixcgGt",
						"F7Aegk6dobnB2x64oSdnTH1hCfYyXHQoVw",
						"2AAmUeKKD2eP6Z5eZ5cHpgtV2tT1Nrg6Gcb"},
					3e9)
				_, _, err := d.Visor.InjectTransaction(tx)
				if err != nil {
					log.Panic(err)
				}
			}
		}()
	}

	select {
	case <-quit:
	case err := <-errC:
		logger.Error(err)
	}

	logger.Info("Shutting down...")
	if rpc != nil {
		rpc.Shutdown()
	}
	if webInterface != nil {
		webInterface.Shutdown()
	}
	d.Shutdown()
	wg.Wait()

	logger.Info("Goodbye")

	if logFile != nil {
		if err := logFile.Close(); err != nil {
			fmt.Println("Failed to close log file")
		}
	}
}

func main() {
	devConfig.Parse()
	Run(&devConfig)
}

// InitTransaction creates the initialize transaction
func InitTransaction() coin.Transaction {
	var tx coin.Transaction

	output := cipher.MustSHA256FromHex("043836eb6f29aaeb8b9bfce847e07c159c72b25ae17d291f32125e7f1912e2a0")
	tx.PushInput(output)

	addrs := visor.GetDistributionAddresses()

	if len(addrs) != 100 {
		log.Panic("Should have 100 distribution addresses")
	}

	// 1 million per address, measured in droplets
	if visor.DistributionAddressInitialBalance != 1e6 {
		log.Panic("visor.DistributionAddressInitialBalance expected to be 1e6*1e6")
	}

	for i := range addrs {
		addr := cipher.MustDecodeBase58Address(addrs[i])
		tx.PushOutput(addr, visor.DistributionAddressInitialBalance*1e6, 1)
	}
	/*
		seckeys := make([]cipher.SecKey, 1)
		seckey := ""
		seckeys[0] = cipher.MustSecKeyFromHex(seckey)
		tx.SignInputs(seckeys)
	*/

	txs := make([]cipher.Sig, 1)
	sig := "ed9bd7a31fe30b9e2d53b35154233dfdf48aaaceb694a07142f84cdf4f5263d21b723f631817ae1c1f735bea13f0ff2a816e24a53ccb92afae685fdfc06724de01"
	txs[0] = cipher.MustSigFromHex(sig)
	tx.Sigs = txs

	tx.UpdateHeader()

	err := tx.Verify()

	if err != nil {
		log.Panic(err)
	}

	log.Printf("signature= %s", tx.Sigs[0].Hex())
	return tx
}

func createDirIfNotExist(dir string) error {
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		return nil
	}

	return os.Mkdir(dir, 0777)
}
