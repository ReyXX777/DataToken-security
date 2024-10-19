# Secure Token Project

## Overview

The **Secure Token Project** is a secure tokenization system built using the **LAMP stack** (Linux, Apache, MySQL, PHP). It features **Multi-Factor Authentication (MFA)** using **Google Authenticator** and securely stores sensitive data using tokenization.

## Features

- **Tokenization**: Convert sensitive data into tokens for secure storage.
- **Detokenization**: Retrieve original data using a token.
- **AES Encryption**: Sensitive data is encrypted before being stored in the database.
- **MFA (Multi-Factor Authentication)**: Secure user accounts with time-based one-time passwords (TOTP).
- **Database**: MySQL is used to store tokens and sensitive data.

## Requirements

- PHP 7.4 or higher
- MySQL
- Apache
- Composer (for managing dependencies)

## Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/your-username/secure-token-project.git
   cd secure-token-project
