# ADB Manager

A desktop app for Linux that lets you look after an Android phone or tablet over USB: manage files, see what every installed app really is, turn off or remove what you don't want, watch what talks to the network, and check the device for signs of compromise, all explained in plain language.

It works through Android's own debugging bridge (`adb`). **No root is needed**, nothing is installed on the phone, and the app never unlocks, flashes or roots anything.

> Written in Python with Tkinter. Four Python files, one folder, no build step.

---

## What it does

### 📁 Files
<img width="1024" height="768" alt="image" src="https://github.com/user-attachments/assets/88162887-0a0a-44c3-a6be-24aa3d6e83b2" />

A two-pane file manager: your computer on the left, the device on the right.

- Copy both ways, create folders, rename, delete
- Show or hide hidden files
- Right-click an APK on the computer side → **Install on device**
- Keys: `F5` copy to the other side · `F7` new folder · `F2` rename · `Del` delete · `Backspace` parent folder · `Ctrl+H` hidden files · `Ctrl+R` refresh

### 📱 Apps
<img width="1024" height="768" alt="image" src="https://github.com/user-attachments/assets/e88cf57c-6400-4f6e-ab13-6375bf28bb71" />

Every installed package, grouped (Google / Android / phone maker / apps you installed), with sub-packages nested under their parent. For each app it tells you, in plain words:

- **What it does**: from a built-in list of ~190 common packages, from Google Play, or from a web search when an app isn't on Play
- **How risky it is to turn off**: safe / caution / critical / unknown. Critical system parts are clearly marked "keep on".
- **What it can access**: its permissions, in plain language

What you can do with apps:

- **Turn OFF / ON** (`pm disable-user` / `pm enable`), with Undo. Nothing is deleted.
- **Uninstall**:
  - apps you installed are removed, and a copy of the APK can be saved to your computer first;
  - system apps are removed *for your user only* (they stay in the system and can be restored);
  - updated system apps can go back to their factory version.
- **Install APKs** from your computer: `.apk` (one or several) and split-app bundles `.apks` / `.xapk` / `.apkm`. Parts for other CPU types are left out, and XAPK game data goes to `Android/obb`.
- **Ask an AI about an app** (optional, see [AI research](#-optional-ai-research)): it compares what the vendor says the package does with independent sources. **Compare AIs** asks two providers and shows where they disagree.
- **Inspect code…**: look inside the app's files without running it (see [Code inspector](#-code-inspector)).

### 🌐 Network
<img width="1024" height="768" alt="image" src="https://github.com/user-attachments/assets/520e5ee4-0a7f-48ac-93f8-f5e486c4a0d3" />

What is happening on the device's network right now, read from Android's own tables (`/proc/net`) and matched to the app that owns each connection. No root needed.

- **Open ports**: what is waiting for connections, and whether only the device itself or *anyone on your Wi-Fi* can reach it
- **Connections**: which app is talking to which server
- Server names are looked up (optional), and auto-refresh highlights newly opened ports
- Optionally **learns** which destinations each app normally uses, keeps a log (CSV), and **warns when an app contacts somewhere new**
- UDP is handled correctly: short-lived client sockets (DNS lookups, fast web traffic) are shown as "temporary", not as open ports

### 🛡️ Security
<img width="1024" height="768" alt="image" src="https://github.com/user-attachments/assets/ef06221a-8310-49f2-a65c-463048f01e11" />

A checkup of the things malware depends on, each result explained with what it means and what to do.

- **Device protection**:
  - security patch level and encryption;
  - bootloader and verified-boot state (green / yellow / orange / red, interpreted correctly);
  - signs of root, ADB over the network, proxy.
- **Powerful access**: which apps hold accessibility, device admin, notification access, screen overlay, usage access, "install other apps", the SMS role or a VPN
- **Origin**: where each app was installed from, and apps with hidden icons
- **Changes since the last check**: new apps, new permissions, **replaced signing certificates**, root appearing
- **Recent use** of camera, microphone, location and contacts
- **Deep scan**:
  - copies every part of each app (main file + all split files), fingerprints and checks each signature;
  - looks the fingerprints up on **VirusTotal** and **MalwareBazaar**;
  - fetches **Exodus Privacy** tracker reports.
  - Malware hidden only in a split file is caught.
- **Device info**: model, chip, Android build, A/B slots, dynamic partitions and more
- **Rooting information**:
  - per-device guidance based on what the device itself reports;
  - optional AI research, with a local database of results.
  - It's advice only: the app never roots, unlocks or flashes.

**Honest by design.** If the phone doesn't answer a question, the app says **"Couldn't check …"**. It never turns a failed check into an all-clear. A good result reads "no common signs", never "clean", because some things (like hidden root) can't be ruled out from outside.

### 🔬 Code inspector
Select one app in the Apps tab and press **Inspect code…**. The app's files are copied to a private temporary folder, read **without ever being run**, and deleted afterwards.

What it finds:

- **Network addresses written inside the app**: web addresses, host names, and raw IPv4 and IPv6 addresses, found in its code, resources, bundled files and native libraries. In full mode each one is traced to the exact code that uses it.
- Each address is classified from evidence:
  - **Expected**, e.g. it belongs to an SDK whose code is inside the app. "Expected" doesn't mean "safe": tracker addresses are expected too.
  - **Worth a look**, with the specific reasons: a raw IP instead of a name, an unusual port, or hidden only in native code.
  - **Not known**: an unfamiliar name is *not* treated as suspicious just for being unfamiliar, and a big-company domain is *not* waved through.
  - Unencrypted `http://` is flagged separately.
- **Code warnings**: loading extra code at run time, running system commands, its own certificate-checking code, trusting user-installed certificates, debug builds, scrambled (obfuscated) code
- **Libraries** recognised inside the app, and the ways it can reach the network

How it's kept safe and honest:

- **Safety**:
  - the analysis runs in a separate process with memory, CPU and time limits, sized from *your* computer;
  - it's killed on Stop;
  - booby-trapped files (decompression bombs, path tricks) are rejected before any parser touches them.
- **Results**:
  - saved per exact app version (package, version and a fingerprint of every part), so an old result is never shown for a new version;
  - an interrupted or partial analysis is shown as **"Analysis incomplete"** and never saved as if it were complete.
- **Limits**: what an app downloads, builds or decrypts *while running* can't be seen by reading its files; the window says so. The Network tab shows what apps actually connect to.

### 🤖 Optional AI research
Uses **Anthropic (Claude)** or **OpenAI**, with web search, through your own API key. Nothing is ever sent to an AI automatically; every request is a button you press.

- **About an app**: what it is, what it collects, known issues. Answers are saved, so an app isn't researched (and billed) twice.
- **About one inspector finding** (*Ask AI about this*):
  - only that one finding is sent, never the app's code;
  - passwords, tokens and query strings are removed first, and you see **the complete text** before confirming;
  - the answer says whether the AI actually searched the web, and which of its listed sources match pages its search really returned.

**Why not Gemini?** Google is excluded on purpose, as a structural precaution: many of the packages being judged are Google's own, so a Google model would be researching its maker's software. This is a conflict-of-interest precaution, not a claim of proven bias.

---

## What leaves your computer, and when

| When | What is sent | To |
|---|---|---|
| You **select an app** in the Apps tab (once per app, then cached) | its package name | Google Play; DuckDuckGo if the app isn't on Play |
| "Look up names of internet servers" is ticked (Network tab) | the IP addresses of connections | your normal DNS resolver |
| You run a **deep scan** with keys set up | file fingerprints (SHA-256) and package names, **never the apps themselves** | VirusTotal, MalwareBazaar, Exodus Privacy |
| You press an **AI button** | the app's details, or one redacted finding (shown to you first) | the AI provider you chose |
| You use the **code inspector** | nothing | — (local only) |

Everything the app saves is kept in `~/.config/adb_manager/`, readable only by your user (files 0600, folders 0700). API keys are stored there too, in `ai_config.json` and `security_config.json`.

---

## Requirements

### Computer
- **Linux.** Developed and tested on Debian 12. It uses Linux/Unix features (process limits, file locking), so **Windows is not supported**; macOS may work but isn't tested.
- **Python 3** with **Tkinter**. Tested with Python 3.11 and 3.12; older Python 3 versions may work but aren't tested.
- **adb** (Android platform-tools), on your `PATH` or pointed to with `ADB=/path/to/adb`

| Distro | Install |
|---|---|
| Debian / Ubuntu | `sudo apt install python3 python3-tk adb` |
| Fedora | `sudo dnf install python3 python3-tkinter android-tools` |
| Arch | `sudo pacman -S python tk android-tools` |

### Phone or tablet
1. Enable **Developer options** (tap *Build number* 7 times in Settings → About)
2. Turn on **USB debugging**
3. Connect by USB and accept the "Allow USB debugging?" prompt on the device

### Optional extras

**AI research**: the official SDKs plus your own API key, set up in the app's *AI settings*:
```
pip install anthropic openai
```
(Install just the one you'll use. On distributions that block system-wide `pip`, use a virtual environment or `pipx`.)

**Deep-scan look-ups**: free keys, set up in the app's *Security settings*:
- [VirusTotal](https://www.virustotal.com/): the free key allows 4 look-ups a minute, so the first deep scan is slow; results are remembered after that
- [MalwareBazaar](https://bazaar.abuse.ch/): auth key
- [Exodus Privacy](https://exodus-privacy.eu.org/): API token

**Code inspector**: Androguard 4.1.4 in its own Python environment (it brings a large set of dependencies, so it's kept away from your system Python). Needs Python 3.9 or newer:
```
python3 -m venv ~/.local/share/adb_manager/inspector-venv
~/.local/share/adb_manager/inspector-venv/bin/pip install androguard==4.1.4
```
If `python3 -m venv` fails, install your system's venv package first (`sudo apt install python3-venv` on Debian/Ubuntu; it's included with Python on Fedora and Arch).

Optional: `readelf` (package `binutils`) lets the inspector list the network functions native libraries use. Without it, native libraries are still scanned for addresses, and the result notes what's missing.

The app detects what's installed and shows these instructions itself when something is missing. It never installs anything on its own.

---

## Installation and running

```
git clone https://github.com/peterpt/Adb-Manager.git
cd Adb-Manager
python3 adb_manager.py
```

Options:
```
python3 adb_manager.py [-s SERIAL] [--local DIR] [--remote DIR]
  -s, --serial   device to connect to (when several are plugged in)
  --local DIR    start folder on this computer (default: current folder)
  --remote DIR   start folder on the device (default: /sdcard)
```

### Files

| File | Role |
|---|---|
| `adb_manager.py` | the app: run this one |
| `app_knowledge.py` | built-in plain-language notes on ~190 packages, risk levels, permission texts |
| `ai_research.py` | AI providers and research requests |
| `security_audit.py` | security checkup, deep scan, rooting database and the code inspector engine |
| `app_tests.py` | developer tests only: not needed to run the app |

All four app files must be in the same folder.

---

## Tests

```
xvfb-run -a python3 -m unittest -v app_tests
```

- Tests never touch your real `~/.config/adb_manager`: they run in a temporary folder.
- Without a display (no `xvfb-run`), the GUI tests are skipped and the rest still run.
- Code-inspector tests that need real APKs use Androguard from the folder above, or from `$ADBM_INSPECTOR_PYTHON`. They download a few small sample APKs once, from Androguard's own test suite at a pinned version, checked against fixed SHA-256 hashes and cached in `~/.cache/adb_manager-test-samples` (or `$ADBM_TEST_SAMPLES`). Without Androguard or a network connection, those tests are **skipped**, never failed.
- One native-library test builds a tiny library with `gcc` and is skipped if `gcc` isn't installed.

---

## Limitations

- The checkup can only see what Android reveals to `adb` without root. Well-hidden root or malware can escape it, which is why results say "no common signs", never "clean".
- The code inspector reads the app's files; it can't see what the app downloads, builds or decrypts while running.
- Turning off or removing system apps can break things: respect the "critical" and "caution" labels.
- The rooting section is information only. Unlocking a bootloader wipes the device and can void warranties.

---

## Third-party tools and services

- [Androguard](https://github.com/androguard/androguard): APK and DEX analysis used by the code inspector
- [VirusTotal](https://www.virustotal.com/), [MalwareBazaar](https://bazaar.abuse.ch/) and [Exodus Privacy](https://exodus-privacy.eu.org/): look-up services for the deep scan
- Android platform-tools (`adb`)

## License

*To be added.*

---

## Credits

*The same credits are shown in the app's **About** window.*

**Project concept & vision**

- [Pedro](https://github.com/peterpt) (https://github.com/peterpt): original idea, product direction and requirements

**Code implementation**

- Claude Opus 5.5 (Anthropic): primary code builder and implementation

**Architecture & security review**

- ChatGPT, GPT-6 (OpenAI): architecture guidance, independent code review and security analysis

**Testing**

- Automated test suite (written by Claude, reviewed by ChatGPT), with results documented per development round
- Real-device testing: Pedro

*Built through human creativity and collaboration between AI systems. Technology is most powerful when used responsibly, transparently and for the benefit of people.*
