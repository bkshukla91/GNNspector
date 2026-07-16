# 🛡️ GNNspector

> **An Advanced Graph Neural Network (GNN) based Static Application Security Testing (SAST) Tool**

GNNspector is a next-generation AI-driven static analysis tool engineered to detect vulnerabilities (such as Buffer Overflows, Command Injections, etc.) in source code. Instead of relying on traditional regular expressions (Regex), it parses source code into structured **Abstract Syntax Trees (AST)** using Tree-sitter, generates deep semantic node features via **Microsoft CodeBERT**, and utilizes a custom **Graph Neural Network (GCN)** architecture to classify files as Safe or Vulnerable.

Post-detection, it routes the telemetry to a hybrid LLM core (Cloud / Local Ollama) to generate a full remediation report and initiates an interactive security assistant patch loop directly inside your terminal.

---

## 📋 Prerequisites & Dependencies

To ensure the scanner operates correctly, your environment must satisfy the following system and software requirements:

### 1. Python Environment
- **Python 3.10 or higher** must be installed on your system.
- **Pip** (Python Package Manager) should be updated to the latest version.
### 2. Ollama & DeepSeek-Coder (Required for Local Offline Mode)
The engine utilizes **Ollama** for hosting local LLMs to guarantee data privacy during code audits.
1. **Install Ollama:** Download and install the application for your operating system from the [Official Ollama Website](https://ollama.com).
2. **Pull the DeepSeek Model:** Open your terminal or command prompt and execute the following command (this is mandatory for the offline pipeline):

### 🚀 Installation & Setup

#### A. Install Ollama (For Linux/Ubuntu)
Run this single command to download and install Ollama automatically:
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

To run the model, use:
```bash
ollama run deepseek-coder:1.3b
```

#### B. Install Ollama (For Windows)
* **Direct Download Link:** [Download Ollama for Windows](https://ollama.com/download/OllamaSetup.exe)
* **Step:** Run the downloaded `OllamaSetup.exe` file and click **Install**.

---

### ⚙️ System Installation Setup

Follow these steps to set up the environment and install GNNspector:

```bash 
# Update system and install dependencies
sudo apt-get update
sudo apt-get install build-essential python3-dev

# Clone the repository and navigate inside
git clone https://github.com/bkshukla91/GNNspector.git
cd GNNspector

# Install Python requirements
pip install -r requirements.txt
pip install -e .

# [OPTIONAL] Set up cloud API key if local Ollama/DeepSeek is not working OPENROUTER_API_KEY="your_actual_api_key_here"

# Run GNNspector
gnnspector path/to/your/target_code.c
```

---

### 📄 3. License
This architecture is distributed under the MIT License - see the [LICENSE](LICENSE) file for open-source compliance details.

* **👨‍💻 Author:** Balkrishna Shukla
* **🏫 Affiliation:** Cyber Security Branch, Engineering College Ajmer (ECA)
