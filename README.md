# Gmail Clone App

A powerful Gmail client built with Flask and deployed on Vercel with AI-powered features.

## Features

- 📧 **Gmail Integration**: Full Gmail API integration for reading, sending, and managing emails
- 🤖 **AI-Powered**: Uses Google Gemini AI for email assistance and smart features
- 🏷️ **Smart Labels**: Automatic email categorization and labeling
- 📱 **Modern UI**: Clean, responsive web interface
- ☁️ **Cloud Ready**: Deployed on Vercel with serverless architecture
- 🔐 **Secure OAuth**: Google OAuth 2.0 authentication

## Tech Stack

- **Backend**: Python Flask
- **AI**: Google Gemini AI
- **APIs**: Gmail API, Google OAuth 2.0
- **Deployment**: Vercel
- **Storage**: Session-based (Vercel compatible)

## Quick Start

### Local Development

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/gmail-clone-app.git
   cd gmail-clone-app
   ```

2. Set up environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your API keys and credentials
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the application:
   ```bash
   python gmail.py
   ```

### Vercel Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for complete deployment instructions.

## Environment Variables

Required environment variables:

- `GEMINI_API_KEY` - Your Google Gemini AI API key
- `FLASK_SECRET_KEY` - Secret key for Flask sessions
- `GOOGLE_OAUTH_CREDENTIALS` - Base64 encoded OAuth credentials (production)
- `CLIENT_SECRETS_FILE_PATH` - Path to credentials.json (local development)

## Security

- ✅ OAuth 2.0 authentication
- ✅ Environment-based configuration
- ✅ No hardcoded secrets
- ✅ Session-based storage
- ✅ Secure credential management

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License.

## Support

For deployment issues, see [DEPLOYMENT.md](DEPLOYMENT.md).
For general questions, open an issue on GitHub.
