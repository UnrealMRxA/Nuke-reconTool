import os
import sys

# import your passive module here
from modules import passive

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def banner():
    print(r"""
                ___     __   ___  __   __       
|\ | |  | |__/ |__     |__) |__  /  ` /  \ |\ | 
| \| \__/ |  \ |___    |  \ |___ \__, \__/ | \| 
                                                 
                  Version 0.1
    """)

def main():
    while True:
        clear()
        banner()

        print("1. Passive Recon")
        print("2. Active Recon")
        print("3. Enumeration")
        print("4. OSINT")
        print("5. Exit\n")

        choice = input("Select option: ").strip()

        if choice == "1":
            passive.run()
        elif choice == "5":
            sys.exit(0)
        else:
            input("Module not implemented yet. Press Enter...")

if __name__ == "__main__":
    main()
