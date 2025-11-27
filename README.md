# PythonStark

**Pure Python ZK-STARK Implementation for Educational Use**

[![License](https://img.shields.io/badge/License-Non--Commercial-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Status](https://img.shields.io/badge/Status-Educational-yellow.svg)]()
[![Security](https://img.shields.io/badge/Security-NOT%20Production%20Ready-red.svg)](SECURITY.md)

---

## ⚠️ SECURITY WARNING

**THIS SOFTWARE IS NOT PRODUCTION READY AND IS NOT CRYPTOGRAPHICALLY SECURE**

This is experimental educational software for learning and research purposes ONLY.

- ❌ NOT audited
- ❌ NOT secure  
- ❌ NOT for production
- ❌ NOT for handling sensitive data

**Read [SECURITY.md](SECURITY.md) before using this software.**

---

## What is PythonStark?

PythonStark is a **zero-knowledge STARK** (Scalable Transparent Argument of Knowledge) proving system implemented entirely in Python. It allows you to generate and verify proofs of computation without revealing the underlying data.

### Purpose

Designed for:
- 📚 **Research and Learning**: Understand how ZK-STARKs work internally
- 🎓 **Educational Use**: Teach zero-knowledge proof concepts
- 🔬 **Experimentation**: Prototype and test ZK proof ideas

---

## Features

- ✅ **Pure Python Implementation**: Easy to understand and modify
- ✅ **FRI-Based STARK Construction**: Fast Reed-Solomon Interactive Oracle Proof
- ✅ **Verkle Tree Commitments**: Efficient vector commitment scheme
- ✅ **Configurable Security**: Adjustable security parameters (80-192 bits)
- ✅ **Educational Focus**: Code clarity prioritized over performance

---

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/SherifSystems/Pythonstark.git
   cd Pythonstark
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the demo**:
   ```bash
   python pythonstark.py
   ```

---

## Usage

### Basic Example

```python
# Import from the main module
from pythonstark import *

# Generate trace
trace = generate_fibonacci_trace_secure(256, mask=False)

# Setup security parameters
security_params = SecurityParameters.compute_parameters(128, 256)

# Create prover and verifier
prover = EnhancedPythonStarkProver(security_params)
verifier = EnhancedPythonStarkVerifier(security_params)

# Generate and verify proof
proof = prover.prove(trace)
valid = verifier.verify(trace, proof)
print(f"Proof valid: {valid}")
```

---

## Project Structure

```
Pythonstark/
├── pythonstark.py             # Main ZK-STARK implementation
├── pythonstark_benchmark.py   # Benchmark script
├── requirements.txt            # Python dependencies
├── LICENSE                     # License file
├── SECURITY.md                 # Security policy and warnings
├── README.md                   # This file
└── .gitignore                  # Git ignore file
```

---

## License

This project is licensed under the **PythonStark License v1.0 (Non-Commercial)**.

### Summary

- ✅ **Free** for research, education, and experimentation
- ✅ **Attribution required**: Must credit SherifSystems
- ❌ **Commercial use prohibited** without separate license
- ❌ **No warranty**: Provided "AS IS"
- ❌ **No liability**: Authors not liable for any damages

For commercial use, contact: **sherifsystems@proton.me**

See [LICENSE](LICENSE) for complete terms.

---

## Contributing

Contributions are welcome for **non-commercial research and educational purposes**.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a Pull Request

---

## Contact

- **GitHub**: https://github.com/SherifSystems/Pythonstark
- **Email**: sherifsystems@proton.me
- **Issues**: Use GitHub Issues for bugs and questions

---

**Remember**: PythonStark is a learning tool. For production needs, use professionally audited, battle-tested libraries.

⭐ Star this repo if you find it useful for learning!

</div>