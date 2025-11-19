#!/usr/bin/env python3
"""
Script to extract MD5 hashes from the vulnerable database
Usage: python extract_hashes.py
"""

import sqlite3
import os

def extract_hashes():
    """Extract all hashes from the database"""
    
    # Path to the vulnerable database
    db_path = '../vulnerable_app/database.db'
    
    if not os.path.exists(db_path):
        print(f"Error: Database not found at {db_path}")
        print("Make sure the vulnerable application has been run at least once.")
        return
    
    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Extract users and their hashes
        cursor.execute("SELECT username, password FROM users")
        users = cursor.fetchall()
        
        if not users:
            print("No users found in the database.")
            print("Create test accounts first through the application.")
            return
        
        # Create the hash file
        output_file = 'hashes.txt'
        with open(output_file, 'w') as f:
            for username, hash_value in users:
                f.write(f"{hash_value}\n")
        
        # Create a detailed file with usernames for reference
        output_file_detailed = 'hashes_detailed.txt'
        with open(output_file_detailed, 'w') as f:
            f.write("Username:Hash\n")
            f.write("-" * 50 + "\n")
            for username, hash_value in users:
                f.write(f"{username}:{hash_value}\n")
        
        print("Extraction successful!")
        print(f"\nStatistics:")
        print(f"   - Number of users: {len(users)}")
        print(f"   - Hash file created: {output_file}")
        print(f"   - Detailed file created: {output_file_detailed}")
        
        print(f"\nExtracted hashes:")
        print("-" * 60)
        for username, hash_value in users:
            print(f"   {username:15s} : {hash_value}")
        print("-" * 60)
        
        print(f"\nNext step:")
        print(f"   Use Hashcat to crack these hashes:")
        print(f"   hashcat -m 0 -a 0 {output_file} rockyou.txt")
        
        conn.close()
        
    except sqlite3.Error as e:
        print(f"SQLite Error: {e}")
    except Exception as e:
        print(f"Error: {e}")

if _name_ == "_main_":
    print("="*60)
    print("MD5 HASH EXTRACTOR")
    print("="*60)
    print("\nThis script extracts MD5 hashes from the vulnerable database")
    print("for brute-force attack demonstration.\n")
    
    extract_hashes()