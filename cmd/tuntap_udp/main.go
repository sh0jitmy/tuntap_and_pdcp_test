package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
)

const (
	udpAddress = "127.0.0.1:12345" // 送信先のUDPアドレス
	mtu        = 1500              // EthernetフレームのMTU
)

// TAPデバイスをセットアップ
func setupTAP() (*water.Interface, error) {
	config := water.Config{
		DeviceType: water.TAP,
	}
	config.Name = "tap0"

	ifce, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("TAPデバイスの作成エラー: %w", err)
	}

	return ifce, nil
}

// TAPデバイスからEthernetフレームを読み取り、UDPで送信
func sendToUDP(ifce *water.Interface, conn *net.UDPConn) {
	frame := make([]byte, mtu)

	for {
		n, err := ifce.Read(frame)
		if err != nil {
			log.Printf("TAP読み取りエラー: %v", err)
			continue
		}

		// EthernetフレームをUDPで送信
		_, err = conn.Write(frame[:n])
		if err != nil {
			log.Printf("UDP送信エラー: %v", err)
		} else {
			log.Printf("UDP送信 %dバイト", n)
		}
	}
}

// UDPから受信したEthernetフレームをTAPデバイスに書き込み
func receiveFromUDP(ifce *water.Interface, conn *net.UDPConn) {
	frame := make([]byte, mtu)

	for {
		n, _, err := conn.ReadFromUDP(frame)
		if err != nil {
			log.Printf("UDP受信エラー: %v", err)
			continue
		}

		// EthernetフレームをTAPに書き込む
		_, err = ifce.Write(frame[:n])
		if err != nil {
			log.Printf("TAP書き込みエラー: %v", err)
		} else {
			log.Printf("TAPに%dバイト書き込み", n)
		}
	}
}

func main() {
	// TAPデバイスのセットアップ
	ifce, err := setupTAP()
	if err != nil {
		log.Fatalf("TAPセットアップエラー: %v", err)
	}
	defer ifce.Close()
	log.Println("TAPデバイス作成完了")

	// UDPソケットのセットアップ
	addr, err := net.ResolveUDPAddr("udp", udpAddress)
	if err != nil {
		log.Fatalf("UDPアドレス解決エラー: %v", err)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Fatalf("UDP接続エラー: %v", err)
	}
	defer conn.Close()
	log.Println("UDPソケット接続完了")

	// 割り込みシグナルをキャッチして、終了時にリソースを解放
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("プログラムを終了します...")
		ifce.Close()
		conn.Close()
		os.Exit(0)
	}()

	// TAPから読み込み、UDPで送信する処理
	go sendToUDP(ifce, conn)

	// UDPから受信し、TAPに書き込む処理
	receiveFromUDP(ifce, conn)
}
