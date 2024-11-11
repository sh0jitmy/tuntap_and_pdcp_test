package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"strings"
	"gopkg.in/yaml.v3"
)

const (
	MTU_SIZE           = 1514              // EthernetフレームのMTU
	PROTO_ICMP         = 1
	PROTO_TCP          = 6 
	PROTO_UDP          = 17
	
	ETH_HEADLEN        = 14
	ETH_ADDRLEN        = 6
	ETH_SRC_OFFSET     = 6
	ETH_TYPE_OFFSET    = 12
	ETH_TYPE_OFFSET_LB = 13
        ETH_TYPE_LEN       = 2
	
	ETH_TYPEIP_U16     = 0x0800 
	ETH_TYPEIP_U8      = 0x08 
	ETH_IP_HTOTLEN      = 38
	ETH_IPPROTO_OFFSET = 23 
	ETH_IPDST_OFFSET   = 30
	ETH_IPDST_LEN      = 4
	ETH_DSTPORT_OFFSET = 36
	ETH_DSTPORT_LEN    = 2
	
	ETH_PDCP_ADDR_OFFSET  = 5
	
	ETH_PDCP_SRC_OFFSET  = 10
	ETH_PDCP_DST_OFFSET  = 11
	ETH_PDCP_RETR_OFFSET = 12
	ETH_PDCP_INTV_OFFSET = 13

	
)

// Config represents the YAML configuration for retransmission flags and MAC addresses
type Config struct {
	MacBaseAddr string
	Sessions map[string] string 
}

type NetConfig struct {
	TapListenAddr string `yaml:"tap_listen"`
	MacSendAddr string `yaml:"mac_send"`
	MacListenAddr string `yaml:"mac_listen"`
	TapSendAddr string `yaml:"tap_send"` 
}

// No uses
// PDCPData represents the structured data to be packed and sent over UDP
type PDCPData struct {
	SrcNode    byte
	DstNode    byte
	Retransmit uint8
	Interleave uint8
	Payload    []byte
}

// loadYAMLConfig reads and parses the retransmission and MAC address configuration from a YAML file
func loadYAMLConfig(filename string) (Config, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return Config{}, fmt.Errorf("YAMLファイルの読み込みエラー: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return Config{}, fmt.Errorf("YAMLパースエラー: %v", err)
	}

	return config, nil
}

// loadYAMLConfig reads and parses the retransmission and MAC address configuration from a YAML file
func loadNetConfig(filename string) (NetConfig, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return NetConfig{}, fmt.Errorf("YAMLファイルの読み込みエラー: %v", err)
	}

	var config NetConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return NetConfig{}, fmt.Errorf("YAMLパースエラー: %v", err)
	}
	return config, nil
}

// checkRetransmission determines if a frame should be retransmitted based on the configuration
func checkRetransmission(config Config, dstIP net.IP, protocol uint8, dstPort uint16) uint8 {
	// キーを生成してYAMLから再送有無を取得
	protoname := getprotoname(protocol)
	//key := fmt.Sprintf("%s-%s-%d-%d-%d", srcIP, dstIP, protocol, srcPort, dstPort)
	key := fmt.Sprintf("%s@%s:%d", protoname,dstIP,dstPort)
	if val, ok := config.Sessions[key]; ok {
		rt,_ := strconv.Atoi(val)
		return uint8(rt) 
	}
	return 0 // デフォルトは再送なし
}

//get protoname fron protocol number
func getprotoname(protocol uint8) string {
	switch protocol {
		case PROTO_ICMP : 
			return "icmp"
		case PROTO_TCP :
			return "tcp"
		case PROTO_UDP :
			return "udp"
		default :
			return "unknown"
	}
	return "unknown"
}



func PDCPDataFromEthernetFrame(config Config, txframe []byte) (error) {
	var dstPort uint16 = 0	
	if len(txframe) < ETH_HEADLEN {
		return fmt.Errorf("不完全なEthernetフレームです")
	}
	// 送信元と宛先MACアドレスを解析
	dstMAC := txframe[0:ETH_ADDRLEN]
	srcMAC := txframe[ETH_SRC_OFFSET:ETH_SRC_OFFSET+ETH_ADDRLEN]
	ethType := binary.BigEndian.Uint16(txframe[ETH_TYPE_OFFSET:ETH_TYPE_OFFSET+ETH_TYPE_LEN])

	// Ethernetフレームのペイロード部分を取得
	if ethType != ETH_TYPEIP_U16 || len(txframe) < ETH_IP_HTOTLEN { // IPv4 (0x0800)であることを確認
		return fmt.Errorf("IPv4ではありません")
	}

	// IPパケットの情報抽出
	dstIP := net.IP(txframe[ETH_IPDST_OFFSET:ETH_IPDST_OFFSET+ETH_IPDST_LEN])
	protocol := txframe[ETH_IPPROTO_OFFSET]
	protoname := getprotoname(protocol)

	if protoname == "icmp" {
		dstPort = 0
	} else  {
		dstPort = binary.BigEndian.Uint16(txframe[ETH_DSTPORT_OFFSET:ETH_DSTPORT_OFFSET+ETH_DSTPORT_LEN])
	}	

	// 再送フラグの判断
	retransmit := checkRetransmission(config, dstIP, protocol,dstPort)

	// 送信元と宛先ノードの取得（MACアドレスの最終オクテット）
	srcNode := srcMAC[ETH_PDCP_ADDR_OFFSET]
	dstNode := dstMAC[ETH_PDCP_ADDR_OFFSET]
	var interleave  byte = 0x00 // interleave short 
	
	//txframeのIPヘッダ以前を上書き
	txframe[ETH_PDCP_SRC_OFFSET] = srcNode
	txframe[ETH_PDCP_DST_OFFSET] = dstNode
	txframe[ETH_PDCP_RETR_OFFSET] = retransmit 
	txframe[ETH_PDCP_INTV_OFFSET] = interleave 

	return  nil
}

// PDCPDataToEthernetFrame converts PDCPData to Ethernet frame using MAC addresses from the configuration
func PDCPDataToEthernetFrame(config Config, rxFrame []byte,basemac []byte) (error) {
	srcNode := rxFrame[ETH_PDCP_SRC_OFFSET]
	dstNode := rxFrame[ETH_PDCP_DST_OFFSET]
	
	copy(rxFrame[0:ETH_ADDRLEN],basemac)
	copy(rxFrame[ETH_SRC_OFFSET:ETH_SRC_OFFSET+ETH_ADDRLEN],basemac)
	
	rxFrame[ETH_PDCP_ADDR_OFFSET] =  dstNode  
	rxFrame[ETH_SRC_OFFSET+ETH_PDCP_ADDR_OFFSET] = srcNode

	//EtherType Set
	rxFrame[ETH_TYPE_OFFSET] = ETH_TYPEIP_U8 
	rxFrame[ETH_TYPE_OFFSET_LB] = 0x00
	return  nil
}


func parseMacAddr(s string)([]byte,error) {

	hexs := strings.ReplaceAll(s, ":", "")
	data, err := hex.DecodeString(hexs)
	if err != nil {
		return nil,err
	}
	return data,nil
}


func main() {
	// YAMLファイルから再送設定とMACアドレスをロード
	config, err := loadYAMLConfig("config.yaml")
	if err != nil {
		log.Fatalf("設定ファイルのロードエラー: %v", err)
	}
	
	// YAMLファイルからネットワーク設定をロード
	netconfig, err := loadNetConfig("netconfig.yaml")
	if err != nil {
		log.Fatalf("設定ファイルのロードエラー: %v", err)
	}

	go xmithandle(config,netconfig)
	go recvhandle(config,netconfig)

	select {}
}

func xmithandle(config Config,netconf NetConfig) { 
	
	//buffer初期化
	buf := make([]byte, MTU_SIZE)
	
	// UDPソケットのセットアップ
	addr, err := net.ResolveUDPAddr("udp", netconf.TapListenAddr)
	if err != nil {
		log.Fatalf("UDPアドレス解決エラー: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("UDPリッスンエラー: %v", err)
	}
	defer conn.Close()
	// UDP送信設定
	sendAddr, err := net.ResolveUDPAddr("udp", netconf.MacSendAddr)
	if err != nil {
		log.Fatalf("UDP送信先アドレス解決エラー: %v", err)
	}
	sendConn, err := net.DialUDP("udp", nil, sendAddr)
	if err != nil {
		log.Fatalf("UDP送信エラー: %v", err)
	}
	defer sendConn.Close()


	for {
		n, srcAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("UDP受信エラー: %v", err)
			continue
		}
		log.Printf("UDPから%dバイトを受信しました (送信元: %v)", n, srcAddr)

		// 受信データをEthernetフレームからPDCPDataに変換し、pack
		err = PDCPDataFromEthernetFrame(config, buf[:n])
		if err != nil {
			log.Printf("PDCPData生成エラー: %v", err)
			continue
		}
		// パックしたデータを送信
		_, err = sendConn.Write(buf[10:n])
		if err != nil {
			log.Printf("UDP送信エラー: %v", err)
		} else {
			log.Printf("UDPでパックされたデータを送信しました")
		}
	}
}

func recvhandle(config Config,netconf NetConfig) { 
	
	buf := make([]byte, MTU_SIZE)
	
	// UDPソケットのセットアップ
	addr, err := net.ResolveUDPAddr("udp", netconf.MacListenAddr)
	if err != nil {
		log.Fatalf("UDPアドレス解決エラー: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("UDPリッスンエラー: %v", err)
	}
	defer conn.Close()

	// UDP送信設定
	sendAddr, err := net.ResolveUDPAddr("udp", netconf.TapSendAddr)
	if err != nil {
		log.Fatalf("UDP送信先アドレス解決エラー: %v", err)
	}
	sendConn, err := net.DialUDP("udp", nil, sendAddr)
	if err != nil {
		log.Fatalf("UDP送信エラー: %v", err)
	}
	defer sendConn.Close()

	//MACアドレス取得	
	basemac ,err := parseMacAddr(config.MacBaseAddr)
	if err != nil {
		log.Fatalf("MACアドレス取得エラー: %v", err)
	}
	for {
		// PDCPDataをUDPで受信
		n, srcAddr, err := conn.ReadFromUDP(buf[10:])
		if err != nil {
			log.Println("UDP受信エラー: %v", err)
			continue
		}
		log.Println("UDPから%dバイトを受信しました (送信元: %v)", n, srcAddr)
		if n > 1504 {
			log.Println("UDP受信サイズオーバー:")
			continue
		}
		// PDCPDataからEthernetフレームに変換
		err = PDCPDataToEthernetFrame(config,buf[:n],basemac) 
		if err != nil {
			log.Printf("Ethernetフレーム生成エラー: %v", err)
			continue
		}
		// EthernetフレームをUDPで送信
		_, err = sendConn.Write(buf[:n])
		if err != nil {
			log.Printf("UDP送信エラー: %v", err)
		} else {
			log.Printf("UDPでEthernetフレームを送信しました")
		}
	}
}
