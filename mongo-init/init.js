// MongoDB initialization script for Signal Chat

// Switch to the signal_chat database
db = db.getSiblingDB('signal_chat');

// Create user for the application
db.createUser({
  user: 'signal_user',
  pwd: 'signal_password',
  roles: [
    {
      role: 'readWrite',
      db: 'signal_chat'
    }
  ]
});

// Create collections with indexes
db.createCollection('identities');
db.createCollection('contacts');
db.createCollection('sessions');
db.createCollection('messages');

// Create indexes for better performance
db.identities.createIndex({ "name": 1 }, { unique: true });
db.contacts.createIndex({ "owner": 1, "name": 1 }, { unique: true });
db.sessions.createIndex({ "owner": 1, "contact_name": 1 }, { unique: true });
db.messages.createIndex({ "owner": 1, "contact_name": 1, "timestamp": 1 });
db.messages.createIndex({ "id": 1 }, { unique: true });

print('Signal Chat database initialized successfully');