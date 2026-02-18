# Chat with BotFriend

A web application where users can chat with a bot that can fetch images and videos based on user queries.

## Features

- User registration and login
- Chat interface with the bot
- Fetch images from Unsplash based on chat messages
- Fetch videos from YouTube based on chat messages
- Text-to-speech for bot responses
- Voice input for user messages

## Setup

### Prerequisites

- Python 3.8+
- Virtual environment (recommended)

### Installation

1. Clone the repository:

    ```sh
    git clone https://github.com/yourusername/chat-with-botfriend.git
    cd chat-with-botfriend
    ```

2. Create and activate a virtual environment:

    ```sh
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3. Install the required packages:

    ```sh
    pip install -r requirements.txt
    ```

4. Set up your environment variables:

    Create a `.env1` file in the project root with the following content:

    ```plaintext
    GROQ_API_KEY=your_groq_api_key
    UNSPLASH_ACCESS_KEY=your_unsplash_access_key
    YOUTUBE_API_KEY=your_youtube_api_key
    SECRET_KEY=your_secret_key
    ```

5. Initialize the database:

    ```sh
    flask db init
    flask db migrate -m "Initial migration."
    flask db upgrade
    ```

6. Run the application:

    ```sh
    flask run
    ```

    The application will be available at `http://127.0.0.1:5000`.

## Usage

- Register a new user or login with an existing account.
- Start chatting with the bot.
- The bot will respond with text, and can also provide images and videos based on your queries.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
