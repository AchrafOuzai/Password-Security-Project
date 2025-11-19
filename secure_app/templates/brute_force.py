#!/usr/bin/env python3
"""
Brute-force script to crack MD5 hashes
Usage: python brute_force.py
"""

import hashlib
import time
from datetime import datetime

def load_hashes(filename='hashes.txt'):
    """Load hashes from a file"""
    try:
        with open(filename, 'r') as f:
            hashes = [line.strip() for line in f if line.strip()]
        return hashes
    except FileNotFoundError:
        print(f"❌ File {filename} not found!")
        print("Run extract_hashes.py first")
        return []

def load_wordlist(filename='rockyou.txt', max_lines=100000):
    """Load a wordlist"""
    try:
        with open(filename, 'r', encoding='latin-1', errors='ignore') as f:
            words = [line.strip() for line in f if line.strip()][:max_lines]
        return words
    except FileNotFoundError:
        print(f"❌ Wordlist {filename} not found!")
        print("Download rockyou.txt or use another wordlist")
        return []

def crack_md5_hash(target_hash, wordlist):
    """Try to crack an MD5 hash"""
    for word in wordlist:
        hash_attempt = hashlib.md5(word.encode()).hexdigest()
        if hash_attempt == target_hash:
            return word
    return None

def brute_force_attack():
    """Run the brute-force attack"""
    
    print("="*70)
    print("🔨 BRUTE-FORCE ATTACK - MD5")
    print("="*70)
    
    # Load hashes
    print("\n📥 Loading hashes...")
    hashes = load_hashes()
    if not hashes:
        return
    
    print(f"   ✅ {len(hashes)} hashes loaded")
    
    # Load wordlist
    print("\n📥 Loading wordlist...")
    wordlist = load_wordlist()
    if not wordlist:
        return
    
    print(f"   ✅ {len(wordlist)} passwords loaded")
    
    # Start attack
    print("\n🚀 Starting attack...")
    print("-"*70)
    
    start_time = time.time()
    results = []
    
    for i, target_hash in enumerate(hashes, 1):
        print(f"\n[{i}/{len(hashes)}] Attempting to crack: {target_hash}")
        
        hash_start = time.time()
        password = crack_md5_hash(target_hash, wordlist)
        hash_time = time.time() - hash_start
        
        if password:
            print(f"   ✅ FOUND! Password: '{password}' (in {hash_time:.2f}s)")
            results.append({
                'hash': target_hash,
                'password': password,
                'time': hash_time,
                'cracked': True
            })
        else:
            print(f"   ❌ Failed (in {hash_time:.2f}s)")
            results.append({
                'hash': target_hash,
                'password': None,
                'time': hash_time,
                'cracked': False
            })
    
    total_time = time.time() - start_time
    
    # Display results
    print("\n" + "="*70)
    print("📊 ATTACK RESULTS")
    print("="*70)
    
    cracked = sum(1 for r in results if r['cracked'])
    success_rate = (cracked / len(results)) * 100
    
    print(f"\n✅ Cracked hashes: {cracked}/{len(results)} ({success_rate:.1f}%)")
    print(f"⏱  Total time: {total_time:.2f} seconds")
    print(f"⚡ Average speed: {len(wordlist)*len(results)/total_time:.0f} hash/s")
    
    print("\n📋 Details:")
    print("-"*70)
    print(f"{'Hash':<35} {'Password':<20} {'Time'}")
    print("-"*70)
    
    for result in results:
        password = result['password'] if result['cracked'] else 'NOT FOUND'
        print(f"{result['hash']:<35} {password:<20} {result['time']:.2f}s")
    
    # Save results
    output_file = 'cracked_passwords.txt'
    with open(output_file, 'w') as f:
        f.write(f"Attack results - {datetime.now()}\n")
        f.write("="*70 + "\n\n")
        f.write("Hash:Password\n")
        f.write("-"*70 + "\n")
        for result in results:
            if result['cracked']:
                f.write(f"{result['hash']}:{result['password']}\n")
    
    print(f"\n💾 Results saved in: {output_file}")
    
    print("\n" + "="*70)
    print("⚠  MD5 VULNERABILITY DEMONSTRATION")
    print("="*70)
    print("\nThis attack demonstrates that:")
    print("1. MD5 hashes are extremely fast to compute")
    print("2. Without a salt, identical passwords produce identical hashes")
    print("3. Wordlists and rainbow tables can crack MD5 easily")
    print("\n✅ Solution: Use bcrypt or Argon2 with a salt!")

if __name__ == "_main_":
    brute_force_attack()