document.addEventListener('DOMContentLoaded', function() {
    // Check if user is authenticated
    const userDropdown = document.getElementById('userDropdown');
    if (userDropdown) {
        // Initialize WebSocket connection
        const socket = io();
        
        // Connection established
        socket.on('connect', function() {
            console.log('WebSocket connected');
        });
        
        // Keep track of notifications
        let notifications = [];
        const notificationBadge = document.getElementById('notification-badge');
        const notificationDropdown = document.getElementById('notification-dropdown');
        const noNotifications = document.getElementById('no-notifications');
        
        // Handle new task notifications
        socket.on('new_task_notification', function(data) {
            console.log('New task notification received:', data);
            
            // Create notification object
            const notification = {
                id: Date.now(),
                title: data.title,
                message: data.message,
                timestamp: new Date(),
                read: false
            };
            
            // Add to notifications array
            notifications.unshift(notification);
            
            // Update UI
            updateNotificationUI();
            
            // Show browser notification if supported
            if (Notification.permission === 'granted') {
                new Notification(notification.title, {
                    body: notification.message,
                    icon: '/static/favicon.ico'
                });
            }
        });
        
        // Handle task update notifications
        socket.on('task_update_notification', function(data) {
            console.log('Task update notification received:', data);
            
            // Create notification object
            const notification = {
                id: Date.now(),
                title: data.title,
                message: data.message,
                timestamp: new Date(),
                read: false
            };
            
            // Add to notifications array
            notifications.unshift(notification);
            
            // Update UI
            updateNotificationUI();
            
            // Show browser notification if supported
            if (Notification.permission === 'granted') {
                new Notification(notification.title, {
                    body: notification.message,
                    icon: '/static/favicon.ico'
                });
            }
        });
        
        // Disconnection
        socket.on('disconnect', function() {
            console.log('WebSocket disconnected');
        });
        
        // Update notification UI
        function updateNotificationUI() {
            // Update badge
            const unreadCount = notifications.filter(n => !n.read).length;
            if (unreadCount > 0) {
                notificationBadge.textContent = unreadCount;
                notificationBadge.style.display = 'inline-block';
            } else {
                notificationBadge.style.display = 'none';
            }
            
            // Update dropdown
            notificationDropdown.innerHTML = '';
            
            if (notifications.length === 0) {
                notificationDropdown.appendChild(noNotifications);
            } else {
                notifications.slice(0, 5).forEach(notification => {
                    const item = document.createElement('li');
                    const link = document.createElement('a');
                    link.classList.add('dropdown-item', 'notification-item');
                    if (!notification.read) {
                        link.classList.add('unread');
                    }
                    
                    link.innerHTML = `
                        <div class="d-flex justify-content-between">
                            <strong>${notification.title}</strong>
                            <small>${formatTimeAgo(notification.timestamp)}</small>
                        </div>
                        <div>${notification.message}</div>
                    `;
                    
                    link.addEventListener('click', function() {
                        notification.read = true;
                        updateNotificationUI();
                    });
                    
                    item.appendChild(link);
                    notificationDropdown.appendChild(item);
                });
                
                if (notifications.length > 5) {
                    const viewAllItem = document.createElement('li');
                    const viewAllLink = document.createElement('a');
                    viewAllLink.classList.add('dropdown-item', 'text-center', 'text-primary');
                    viewAllLink.textContent = 'View all notifications';
                    viewAllLink.href = '#'; // Add a notifications page if needed
                    viewAllItem.appendChild(viewAllLink);
                    notificationDropdown.appendChild(viewAllItem);
                }
            }
        }
        
        // Request browser notification permission
        if (Notification.permission !== 'granted' && Notification.permission !== 'denied') {
            Notification.requestPermission();
        }
    }
    
    // Format time ago utility function
    function formatTimeAgo(date) {
        const seconds = Math.floor((new Date() - date) / 1000);
        
        let interval = seconds / 31536000;
        if (interval > 1) {
            return Math.floor(interval) + ' years ago';
        }
        
        interval = seconds / 2592000;
        if (interval > 1) {
            return Math.floor(interval) + ' months ago';
        }
        
        interval = seconds / 86400;
        if (interval > 1) {
            return Math.floor(interval) + ' days ago';
        }
        
        interval = seconds / 3600;
        if (interval > 1) {
            return Math.floor(interval) + ' hours ago';
        }
        
        interval = seconds / 60;
        if (interval > 1) {
            return Math.floor(interval) + ' minutes ago';
        }
        
        return 'just now';
    }
});
// Connect to WebSocket when on task detail page
if (window.location.pathname.includes('/task/')) {
    const socket = io();
    const taskId = window.location.pathname.split('/').pop();
    
    // Listen for task update notifications
    socket.on('task_update_notification', function(data) {
        // Create notification
        const notification = document.createElement('div');
        notification.className = 'toast show position-fixed bottom-0 end-0 m-3';
        notification.setAttribute('role', 'alert');
        notification.setAttribute('aria-live', 'assertive');
        notification.setAttribute('aria-atomic', 'true');
        notification.style.zIndex = 1050;
        
        notification.innerHTML = `
            <div class="toast-header">
                <strong class="me-auto">${data.title}</strong>
                <button type="button" class="btn-close" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
            <div class="toast-body">
                ${data.message}
                <div class="mt-2 pt-2 border-top">
                    <button type="button" class="btn btn-sm btn-primary refresh-page">
                        Refresh Page
                    </button>
                </div>
            </div>
        `;
        
        document.body.appendChild(notification);
        
        // Add event listener to refresh button
        notification.querySelector('.refresh-page').addEventListener('click', function() {
            window.location.reload();
        });
        
        // Auto-dismiss after 10 seconds
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => notification.remove(), 500);
        }, 10000);
    });
    
    // Optional: Join a room specific to this task
    socket.emit('join_task_room', { task_id: taskId });
}

function createStatusChart(pendingTasks, inProgressTasks, completedTasks) {
    const ctx = document.getElementById('statusChart').getContext('2d');
    
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Pending', 'In Progress', 'Completed'],
            datasets: [{
                data: [pendingTasks, inProgressTasks, completedTasks],
                backgroundColor: ['#FFC107', '#17A2B8', '#28A745'],
                borderColor: 'white',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom'
                },
                title: {
                    display: true,
                    text: 'Task Status Overview',
                    font: { size: 16 }
                }
            }
        }
    });
}

// Task Priority Distribution Chart
function createPriorityChart() {
    fetch('/api/tasks')
        .then(response => response.json())
        .then(tasks => {
            const priorityCounts = {
                'low': 0,
                'medium': 0,
                'high': 0
            };
            
            tasks.forEach(task => {
                priorityCounts[task.priority]++;
            });
            
            const ctx = document.getElementById('priorityChart').getContext('2d');
            
            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: ['Low', 'Medium', 'High'],
                    datasets: [{
                        label: 'Task Count',
                        data: [priorityCounts.low, priorityCounts.medium, priorityCounts.high],
                        backgroundColor: ['#28A745', '#FFC107', '#DC3545'],
                        borderColor: 'white',
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            precision: 0
                        }
                    },
                    plugins: {
                        title: {
                            display: true,
                            text: 'Task Priority Distribution',
                            font: { size: 16 }
                        }
                    }
                }
            });
        });
}

// Initialize charts when document is ready
document.addEventListener('DOMContentLoaded', function() {
    // Get task counts from the HTML data attributes or API
    const pendingTasks = parseInt(document.getElementById('pending-count').dataset.count);
    const inProgressTasks = parseInt(document.getElementById('progress-count').dataset.count);
    const completedTasks = parseInt(document.getElementById('completed-count').dataset.count);
    
    createStatusChart(pendingTasks, inProgressTasks, completedTasks);
    createPriorityChart();
});