# Task Management System

A collaborative task management application built with Flask and SQLAlchemy. This application allows users to create, assign, and track tasks with features like real-time notifications and data visualization.

## Features

- **User Authentication**: Register, login, and role-based authorization
- **Task Management**: Create, assign, update, and delete tasks
- **Task Categorization**: Set priorities and track status
- **Dashboard**: Visual representation of task statistics with charts
- **Real-time Notifications**: Get notified when tasks are assigned or updated
- **RESTful API**: Programmatically interact with tasks

## Technologies Used

- **Backend**: Flask, SQLAlchemy, Flask-SocketIO
- **Frontend**: HTML, CSS, JavaScript, Bootstrap 5
- **Database**: SQLite (development), PostgreSQL (production-ready)
- **Data Visualization**: Chart.js
- **Real-time Communication**: Socket.IO

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/MohanCode666/task-management-system.git
   cd task-management-system
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Create a `.env` file in the project root with:
   ```
   SECRET_KEY=your_secret_key
   DATABASE_URL=sqlite:///task_manager.db  # For development
   ```

5. Run the application:
   ```
   python app.py
   ```

6. Access the application at `http://localhost:5000`

## API Documentation

The application provides a RESTful API:

- `GET /api/tasks`: Get all tasks for the current user
- `GET /api/tasks/{task_id}`: Get a specific task
- `PATCH /api/tasks/{task_id}/status`: Update a task's status

## Deployment

The application is ready for deployment to platforms like Render:

1. Create a new web service on Render
2. Link to your GitHub repository
3. Set environment variables (SECRET_KEY, DATABASE_URL)
4. Deploy the application

## Project Structure

```
/task_