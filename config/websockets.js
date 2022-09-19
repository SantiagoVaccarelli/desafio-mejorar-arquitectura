const mensajes = [];

export default (io) => {
    io.on('connection', (socket) => {
        console.log('New user connected. Soquet ID : ', socket.id);
        socket.on('set-user', (user) => {
            console.log('Current User Data', user);
        });
    
        socket.on('new-message', (message) => {
            console.log('New Message', message);
            mensajes.push(message);
            socket.emit('all-messages', mensajes);
            socket.broadcast.emit('all-messages',mensajes);
        });

        socket.on('disconnect', (user) => {
            console.log('User disconnected:', user);
        });
    
    });
};