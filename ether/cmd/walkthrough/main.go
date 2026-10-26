// Command walkthrough shows, step by step, that the Ethereum-style chain works
// as a blockchain should: accounts are created from key pairs, transfers are
// signed, included in blocks, validated by another node, balances and nonces
// change, invalid transactions are rejected and tampering is detected.
//
//	go run ./cmd/walkthrough                 # K12 with the proposed S-box (default)
//	go run ./cmd/walkthrough -hash keccak    # same scenario on Keccak-256
//
// On Windows run `chcp 65001` first so the Vietnamese text displays correctly.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"k12chain/chain"
)

const (
	chainGasPrice = 1
	gasLimit      = 21000
)

var h chain.Hasher

func main() {
	name := flag.String("hash", "k12sbox", "hàm băm: "+strings.Join(chain.HasherNames, ", "))
	flag.Parse()
	var ok bool
	if h, ok = chain.HasherByName(*name); !ok {
		fmt.Fprintln(os.Stderr, "không có hàm băm", *name)
		os.Exit(1)
	}
	run()
}

func step(n int, title string) {
	fmt.Printf("\n%s\n BƯỚC %d. %s\n%s\n", strings.Repeat("=", 74), n, title, strings.Repeat("=", 74))
}

func short(s string) string { return s[:10] + "…" + s[len(s)-8:] }

type user struct {
	name string
	key  *chain.Key
	addr chain.Address
}

func balances(bc *chain.Blockchain, users []user) {
	fmt.Printf("   %-6s %-44s %12s %6s\n", "Tên", "Địa chỉ", "Số dư", "Nonce")
	for _, u := range users {
		fmt.Printf("   %-6s %-44s %12d %6d\n", u.name, u.addr.Hex(), bc.State().Balance(u.addr), bc.State().Nonce(u.addr))
	}
}

func transfer(bc *chain.Blockchain, from user, to chain.Address, value uint64, nonce uint64) *chain.Transaction {
	tx := &chain.Transaction{Nonce: nonce, GasPrice: chainGasPrice, GasLimit: gasLimit, To: to, Value: value, ChainID: bc.Cfg.ChainID}
	if err := tx.Sign(h, from.key); err != nil {
		panic(err)
	}
	return tx
}

// precheck executes tx on a scratch copy of the state to explain why a
// transaction will or will not be accepted.
func precheck(bc *chain.Blockchain, label string, tx *chain.Transaction) {
	_, err := bc.State().Copy().ApplyTransaction(h, tx, chain.Address{}, bc.Cfg.ChainID)
	if err == nil {
		fmt.Printf("   [HỢP LỆ]   %s\n", label)
		return
	}
	fmt.Printf("   [TỪ CHỐI]  %s\n              lý do: %s\n", label, vi(err))
}

func showBlock(bc *chain.Blockchain, blk *chain.Block) {
	hd := blk.Header
	fmt.Printf("   Khối số           : %d (slot %d)\n", hd.Number, hd.Slot)
	fmt.Printf("   Validator đề xuất : #%d\n", hd.ProposerIndex)
	fmt.Printf("   Số giao dịch      : %d\n", len(blk.Txs))
	fmt.Printf("   Số phiếu bầu      : %d\n", len(blk.Attestations))
	fmt.Printf("   Hash khối cha     : %s\n", hd.ParentHash.Hex())
	fmt.Printf("   Tx root           : %s\n", hd.TxRoot.Hex())
	fmt.Printf("   State root        : %s\n", hd.StateRoot.Hex())
	fmt.Printf("   Hash khối         : %s\n", blk.Hash(h).Hex())
}

func run() {
	fmt.Printf("MÔ PHỎNG MẠNG KIỂU ETHEREUM — hàm băm: %s\n", h.Name())

	// ------------------------------------------------------------------
	step(1, "TẠO TÀI KHOẢN (cặp khóa -> địa chỉ = 20 byte cuối của H(khóa công khai))")
	var users []user
	for _, n := range []string{"Alice", "Bob", "Carol"} {
		k, err := chain.GenerateKey()
		if err != nil {
			panic(err)
		}
		u := user{n, k, k.Address(h)}
		users = append(users, u)
		pub := fmt.Sprintf("%x", k.PubBytes())
		fmt.Printf("   %-6s khóa công khai %s\n          địa chỉ        %s\n", n, short(pub), u.addr.Hex())
	}
	alice, bob, carol := users[0], users[1], users[2]

	// ------------------------------------------------------------------
	step(2, "KHỞI TẠO MẠNG (khối genesis, 4 validator PoS, 2 node)")
	vals, vkeys, err := chain.GenerateValidators(h, 4, 32_000_000_000)
	if err != nil {
		panic(err)
	}
	alloc := map[chain.Address]uint64{alice.addr: 1_000_000, bob.addr: 500_000}
	cfg := chain.DefaultConfig()
	producer := chain.NewBlockchain(h, cfg, chain.NewPoSEngine(vals, vkeys), alloc)
	follower := chain.NewBlockchain(h, cfg, chain.NewPoSEngine(vals, nil), alloc) // chỉ xác thực, không có khóa
	fmt.Printf("   Node đề xuất khối (producer) genesis: %s\n", producer.Genesis().Hash(h).Hex())
	fmt.Printf("   Node xác thực    (follower) genesis: %s\n", follower.Genesis().Hash(h).Hex())
	fmt.Printf("   Hai node có cùng genesis: %v\n", producer.Genesis().Hash(h) == follower.Genesis().Hash(h))
	fmt.Println("\n   Số dư ban đầu:")
	balances(follower, users)

	// ------------------------------------------------------------------
	step(3, "CHUYỂN TIỀN: Alice gửi Bob 250000 (phí gas = 21000 × 1)")
	tx1 := transfer(producer, alice, bob.addr, 250_000, 0)
	from, err := tx1.Sender(h)
	fmt.Printf("   Hash giao dịch    : %s\n", tx1.Hash(h).Hex())
	fmt.Printf("   Chữ ký hợp lệ     : %v (người gửi khôi phục = %s)\n", err == nil, from.Hex())
	fmt.Printf("   Người gửi đúng là Alice: %v\n", from == alice.addr)

	// ------------------------------------------------------------------
	step(4, "TẠO KHỐI 1 VÀ NODE KHÁC XÁC THỰC")
	blk1, st, err := producer.ProduceBlock([]*chain.Transaction{tx1}, chain.Address{})
	if err != nil {
		panic(err)
	}
	showBlock(producer, blk1)
	fmt.Printf("   Giao dịch được đưa vào khối: %d, bị loại: %d\n", st.Included, st.Dropped)
	err = follower.InsertBlock(blk1)
	fmt.Printf("\n   Follower xác thực khối 1: %s\n", okStr(err))
	fmt.Println("\n   Số dư sau khối 1 (Alice: 1000000 − 250000 − 21000 = 729000):")
	balances(follower, users)

	// ------------------------------------------------------------------
	step(5, "NHIỀU GIAO DỊCH, TRONG ĐÓ CÓ GIAO DỊCH KHÔNG HỢP LỆ")
	tx2 := transfer(producer, bob, carol.addr, 100_000, 0)
	tx3 := transfer(producer, alice, carol.addr, 50_000, 1)
	bad1 := transfer(producer, carol, alice.addr, 10_000_000, 0) // Carol chưa có đủ tiền
	bad2 := transfer(producer, alice, bob.addr, 1, 0)            // dùng lại nonce 0 (tấn công phát lại)
	bad3 := transfer(producer, bob, carol.addr, 1_000, 1)
	bad3.Value = 400_000 // sửa số tiền SAU khi ký -> chữ ký không còn khớp
	precheck(producer, "Bob -> Carol 100000 (nonce 0)", tx2)
	precheck(producer, "Alice -> Carol 50000 (nonce 1)", tx3)
	precheck(producer, "Carol -> Alice 10000000 (vượt số dư)", bad1)
	precheck(producer, "Alice -> Bob 1 (dùng lại nonce 0)", bad2)
	precheck(producer, "Bob -> Carol (số tiền bị sửa sau khi ký)", bad3)

	beforeBlk2 := follower.Clone() // một node khác dừng ở khối 1, dùng ở bước 7
	blk2, st, err := producer.ProduceBlock([]*chain.Transaction{tx2, tx3, bad1, bad2, bad3}, chain.Address{})
	if err != nil {
		panic(err)
	}
	fmt.Printf("\n   Khối 2: đưa vào %d giao dịch, loại %d giao dịch không hợp lệ\n", st.Included, st.Dropped)
	showBlock(producer, blk2)
	err = follower.InsertBlock(blk2)
	fmt.Printf("\n   Follower xác thực khối 2: %s\n", okStr(err))
	fmt.Println("\n   Số dư sau khối 2:")
	balances(follower, users)
	fmt.Printf("\n   State root của hai node trùng nhau: %v\n", producer.State().Root(h) == follower.State().Root(h))

	// ------------------------------------------------------------------
	step(6, "BẰNG CHỨNG MERKLE (light client kiểm tra giao dịch có trong khối)")
	leaves := make([][]byte, len(blk2.Txs))
	for i, tx := range blk2.Txs {
		leaves[i] = tx.RLP()
	}
	proof := chain.MerkleProof(h, leaves, 1)
	fmt.Printf("   Giao dịch Alice -> Carol nằm ở vị trí 1 của khối 2, bằng chứng gồm %d bước\n", len(proof))
	fmt.Printf("   Kiểm tra với tx root trong header : %v\n", chain.VerifyMerkleProof(h, blk2.Header.TxRoot, leaves[1], proof))
	forged := append([]byte(nil), leaves[1]...)
	forged[len(forged)-1] ^= 1
	fmt.Printf("   Kiểm tra với giao dịch bị sửa 1 bit: %v\n", chain.VerifyMerkleProof(h, blk2.Header.TxRoot, forged, proof))

	// ------------------------------------------------------------------
	step(7, "PHÁT HIỆN GIẢ MẠO")
	// (a) a node receives a copy of block 2 whose transaction was altered
	fake := *blk2
	fake.Txs = append([]*chain.Transaction(nil), blk2.Txs...)
	altered := *fake.Txs[0]
	altered.Value = 999_999
	fake.Txs[0] = &altered
	err = beforeBlk2.Clone().InsertBlock(&fake)
	fmt.Printf("   (a) Khối 2 bị sửa số tiền giao dịch gửi tới node khác: %s\n", okStr(err))
	// (b) someone edits a transaction already stored in the chain
	stored := follower.Block(1).Txs[0]
	stored.Value++
	err = follower.Verify()
	stored.Value--
	fmt.Printf("   (b) Sửa một giao dịch đã lưu trong khối 1, kiểm tra lại chuỗi: %s\n", verifyStr(err))
	fmt.Printf("   (c) Kiểm tra lại toàn chuỗi sau khi hoàn tác: %s\n", verifyStr(follower.Verify()))

	// ------------------------------------------------------------------
	step(8, "TỔNG KẾT")
	fmt.Printf("   Chiều cao chuỗi       : %d khối (kể cả genesis)\n", follower.Len())
	fmt.Printf("   Khối đã chốt (final)  : %d (>= 2/3 stake đã bỏ phiếu)\n", follower.Finalized)
	fmt.Printf("   Hàm băm sử dụng       : %s (địa chỉ, giao dịch, chữ ký, Merkle root, state root, hash khối)\n", h.Name())
}

// vi explains the chain's (English) error messages in Vietnamese.
func vi(err error) string {
	switch {
	case errors.Is(err, chain.ErrInsufficient):
		return "không đủ số dư cho số tiền + phí gas (" + err.Error() + ")"
	case errors.Is(err, chain.ErrNonce):
		return "sai nonce, giao dịch bị phát lại hoặc sai thứ tự (" + err.Error() + ")"
	case errors.Is(err, chain.ErrBadSignature):
		return "chữ ký không hợp lệ (" + err.Error() + ")"
	case errors.Is(err, chain.ErrBadTxRoot):
		return "tx root không khớp với nội dung giao dịch (" + err.Error() + ")"
	case errors.Is(err, chain.ErrBadStateRoot):
		return "state root không khớp (" + err.Error() + ")"
	}
	return err.Error()
}

func okStr(err error) string {
	if err == nil {
		return "CHẤP NHẬN"
	}
	return "TỪ CHỐI — " + vi(err)
}

func verifyStr(err error) string {
	if err == nil {
		return "chuỗi toàn vẹn"
	}
	return "PHÁT HIỆN GIẢ MẠO — " + vi(err)
}
