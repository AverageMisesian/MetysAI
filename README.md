# MetysAI - Disassembler

AI-powered binary analysis tool that combines **Radare2** disassembly with **ChatGPT**  for interactive reverse engineering. Basically, vibe reverse engineering. 

## 🚀 Features

### 🔍 Binary Analysis
- **Full Binary Disassembly**: Complete disassembly of executable files using Radare2
- **Symbol Tree**: Organized view of functions, imports, exports, and strings
<img width="661" height="322" alt="image" src="https://github.com/user-attachments/assets/fcdfcb2e-eb83-4a10-bfa9-aff6ec8f33a2" />



### 🤖 AI-Powered Analysis
- **ChatGPT Integration**: Chat directly with ChatGPT about your binary analysis
- **Contextual Understanding**: Full disassembly is automatically provided as context to ChatGPT
- **Python Code Generation**: Convert assembly code to Python with the "Analyze Full Disassembly to Python" button
- **Interactive Q&A**: Ask questions about functions, vulnerabilities, code patterns, and more
  <img width="700" height="333" alt="image" src="https://github.com/user-attachments/assets/e5da4dd7-0722-416f-8502-4e961b3b9d56" />
<img width="590" height="411" alt="image" src="https://github.com/user-attachments/assets/e334f01f-326e-447d-8193-42ad0a4d2b8d" />


### 📁 Supported Features
- **Imports & Exports**: View and analyze imported/exported functions
- **String Analysis**: Extract and analyze strings from the binary
- **Cross-References**: View function cross-references and relationships
- **Multiple Formats**: Support for various executable formats through Radare2

## ⚙️ Configuration

1. **Configure OpenAI API Key**:
   Edit `dist/win-unpacked/config.json`:
   ```json
   {
     "openai_api_key": "your-openai-api-key-here",
     "openai_model": "gpt-4o",
     "openai_prompt": "You are an expert reverse engineer. Convert the following assembly code into equivalent Python code. Only output the Python code, no explanations."
   }
   ```

2. **Customize Analysis**:
   - Modify the `openai_model` to use different GPT models
   - Adjust the `openai_prompt` for different analysis styles


## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Electron UI   │◄──►│   Go Backend    │◄──►│    Radare2      │
│   (Frontend)    │    │   (main.go)     │    │   (Analysis)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                                              
         ▼                                              
┌─────────────────┐                                     
│  OpenAI API     │                                     
│  (ChatGPT)      │                                     
└─────────────────┘                                     
```

- **Frontend**: Electron app with HTML/CSS/JavaScript
- **Backend**: Go server that interfaces with Radare2
- **Analysis Engine**: Radare2 for binary analysis and disassembly
- **AI Integration**: OpenAI API for intelligent analysis and code generation

### Key Components
- **Symbol Tree**: Dynamic tree view of binary symbols
- **Listing Panel**: Syntax-highlighted disassembly display
- **Chat Panel**: Real-time ChatGPT integration

## 🤝 Contributing
1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit your changes: `git commit -am 'Add feature'`
4. Push to the branch: `git push origin feature-name`
5. Submit a pull request

## 📝 License

This project is licensed under the Attribution-NonCommercial-ShareAlike 4.0 International - see the [LICENSE](LICENSE) file for details.

**Commercial use requires a separate license.** For commercial licensing inquiries, please contact: daniel@metysai.info

## 🙏 Acknowledgments

- **Radare2 Team** for the powerful reverse engineering framework
- **OpenAI** for ChatGPT API
- **Electron Team** for the cross-platform desktop framework

## 🐛 Known Issues

- Windows users may see `'chcp' is not recognized` warnings (cosmetic only)
- Large binaries may take time to analyze

## 📞 Support

- Create an issue on GitHub for bug reports
- Review OpenAI API documentation for ChatGPT integration issues
- Contact email: daniel@metysai.info

---

**Happy Reverse Engineering!** 🔍✨ 
