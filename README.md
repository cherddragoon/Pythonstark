# PythonStark

**Pure Python ZK-STARK Implementation for Research and Educational Use**

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

### Performance

| Computation Steps | Proof Time | Verification Time | Memory Usage |
|-------------------|------------|-------------------|--------------|
| 256 steps         | ~75ms      | ~0.009ms          | ~108 MB      |
| 512 steps         | ~107ms     | ~0.010ms          | ~104 MB      |
| 1024 steps        | ~161ms     | ~0.012ms          | ~118 MB      |
| 2048 steps        | ~232ms     | ~0.015ms          | ~111 MB      |

*Note: These are educational benchmarks, not production-grade performance.*

---

## Installation

### Quick Start

1. **Clone the repository**:
   ```bash
   git clone https://github.com/SherifSystems/Pythonstark.git
   cd Pythonstark
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation**:
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

### Running the Demo

```bash
# Basic demonstration
python pythonstark.py

# Run benchmarks
python pythonstark_benchmark.py
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

## Security Considerations

**DO NOT USE FOR**:
- 🚫 Cryptocurrency wallets or key management
- 🚫 Financial transaction systems
- 🚫 Authentication or access control
- 🚫 Production deployments of any kind

**SAFE FOR**:
- ✅ Learning how ZK-STARKs work
- ✅ Academic research projects
- ✅ Teaching cryptography concepts
- ✅ Prototyping and experimentation

See [SECURITY.md](SECURITY.md) for complete security details.

---

## License

This project is licensed under the **PythonStark License v1.0 (Non-Commercial)**.

### Summary

- ✅ **Free** for research, education, and experimentation
- ✅ **Attribution required**: Must credit SherifSystems
- ❌ **Commercial use prohibited** without separate license
- ❌ **No warranty**: Provided "AS IS"
- ❌ **No liability**: Authors not liable for any damages

### Commercial Licensing

For commercial use, contact:
- **Email**: sherifsystems@proton.me
- **GitHub**: https://github.com/SherifSystems
- **Repository**: https://github.com/SherifSystems/Pythonstark

See [LICENSE](LICENSE) for complete terms.

---

## Contributing

Contributions are welcome for **non-commercial research and educational purposes**.

### How to Contribute

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes following coding standards
4. Test thoroughly
5. Commit your changes: `git commit -m 'Add your feature'`
6. Push to branch: `git push origin feature/your-feature`
7. Open a Pull Request

### Contribution Guidelines

- ✅ Follow existing code style and structure
- ✅ Add documentation for new features
- ✅ Include tests for new functionality
- ✅ Maintain educational clarity
- ✅ Follow the non-commercial license

---

## FAQ

**Q: Can I use this in production?**  
A: **NO**. This is educational software and is not secure for production use.

**Q: Is this cryptographically secure?**  
A: **NO**. It has not been audited and contains known security limitations.

**Q: Can I use this for my startup/company?**  
A: Only with a commercial license. Contact us for licensing options.

**Q: Why Python? It's slow!**  
A: Educational clarity is prioritized over performance. Python makes the code accessible for learners.

**Q: What field is used for the finite field arithmetic?**  
A: Check the source code in `pythonstark.py` for the Goldilocks prime field implementation.

**Q: How large are the proofs?**  
A: Proof size varies based on security parameters and computation size. Typically several KB for small computations.

**Q: Can I modify the code?**  
A: Yes! Under the non-commercial license, you can modify for research/education. See [LICENSE](LICENSE).

**Q: Does this implement recursive proofs?**  
A: Not currently. This is planned for future versions.

**Q: What ZK property does this provide?**  
A: Computational integrity with zero-knowledge. The verifier learns nothing about the input except that the computation was performed correctly.

### Legal Questions

**Q: Can I use this in my country?**  
A: Check your local cryptographic software regulations. You are responsible for compliance.

**Q: Is this really free?**  
A: Yes, for non-commercial research and educational use. Commercial use requires a license.

**Q: What if I find a security vulnerability?**  
A: This is educational software with known limitations. See [SECURITY.md](SECURITY.md) for our security policy.

---

## Acknowledgments

### Inspiration and References

- **STARK Protocol**: Based on research by Eli Ben-Sasson et al.
- **ZK-STARK Papers**: Academic research on scalable zero-knowledge proofs
- **FRI Protocol**: Fast Reed-Solomon Interactive Oracle Proofs
- **Verkle Trees**: Efficient vector commitment schemes

### Contributors

- Developed and maintained by **SherifSystems**
- Contributions from the open-source community
- Inspired by the broader ZK research community

### Educational Resources

For learning more about ZK-STARKs:
- **StarkWare Blog**: https://medium.com/starkware
- **STARK Paper**: "Scalable, transparent, and post-quantum secure computational integrity" (Ben-Sasson et al.)
- **ZK Learning Resources**: https://zkp.science/

---

## Support and Contact

### Getting Help

- **Documentation**: Read this README and [SECURITY.md](SECURITY.md)
- **Issues**: Open an issue on GitHub for bugs or questions
- **Discussions**: Use GitHub Discussions for conceptual questions

### Contact Information

- **GitHub**: https://github.com/SherifSystems
- **Repository**: https://github.com/SherifSystems/Pythonstark
- **Email**: sherifsystems@proton.me

### Reporting Issues

When reporting issues, please include:
- Python version
- Operating system
- Full error message
- Steps to reproduce
- Expected vs actual behavior

---

## Citation

If you use PythonStark in academic research, please cite:

```bibtex
@software{pythonstark2025,
  author = {SherifSystems},
  title = {PythonStark: Pure Python ZK-STARK Implementation},
  year = {2025},
  url = {https://github.com/SherifSystems/Pythonstark},
  note = {Educational implementation of ZK-STARK protocol}
}
```

---

## Disclaimer

**BY USING THIS SOFTWARE, YOU ACKNOWLEDGE AND AGREE**:

1. ✅ This software is for **EDUCATIONAL AND RESEARCH PURPOSES ONLY**
2. ✅ It is **NOT SECURE** for production or security-critical use
3. ✅ It has **NOT BEEN AUDITED** by security professionals
4. ✅ You **ACCEPT ALL RISKS** associated with using this software
5. ✅ Authors provide **NO WARRANTIES OR GUARANTEES**
6. ✅ Authors are **NOT LIABLE** for any damages or losses
7. ✅ You are **RESPONSIBLE FOR COMPLIANCE** with applicable laws
8. ✅ You will **NOT USE** for prohibited purposes (see LICENSE)

**IF YOU DO NOT AGREE, DO NOT USE THIS SOFTWARE.**

See [LICENSE](LICENSE) for complete legal terms.  
See [SECURITY.md](SECURITY.md) for security disclosures.

---

## Version

**Current Version**: 1.0  
**Last Updated**: November 27, 2025  
**Status**: Active Development

---

## Additional Resources

### Learn More About ZK-STARKs

- **StarkWare Resources**: https://starkware.co/developers/
- **ZK Learning**: https://zkhack.dev/
- **Academic Papers**: Search for "ZK-STARK" on eprint.iacr.org

### Related Projects

- **zkSNARKs**: Different ZK proof system (trusted setup required)
- **Bulletproofs**: Range proofs without trusted setup
- **Plonk**: Universal ZK-SNARKs

### Community

- **ZK Research Forum**: https://zkresear.ch/
- **Ethereum ZK Community**: Active research on ZK rollups

---

**Remember**: PythonStark is a learning tool. For production needs, use professionally audited, battle-tested libraries.

---

<div align="center">

**Made with ❤️ for the ZK research and education community**

⭐ Star this repo if you find it useful for learning!

</div>