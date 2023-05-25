const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const app = express();

app.use(express.json());

var ObjectId = require('mongodb').ObjectID;

            // Connect to MongoDB

mongoose.connect('mongodb://localhost:27017/articles', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB.');
});

            // Define User schema

const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  name: String,
  age: Number,
});
const User = mongoose.model('User', userSchema);

            // Define Article schema

const articleSchema = new mongoose.Schema({
  title: String,
  description: String,
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
});
const Article = mongoose.model('Article', articleSchema);
            // API to signup a user

app.post('/api/signup', async (req, res) => {
    try {
        const { email, password, name, age } = req.body;
    // Check if the email is already taken
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({
        statusCode: 409,
        error: 'Conflict!',
        message: 'Email already exists.',
      });
    }

                // Hash the password
    const passwordHashed = await bcrypt.hash(password, 10);
                // Create a new user
    const newUser = new User({
      email,
      password: passwordHashed,
      name,
      age,
    });
    await newUser.save();

    res.status(201).json({
      statusCode: 201,
      data: {
        data: newUser,
      },
      message: 'The user is created successfully.',
    });
} catch (error) {
    console.error(error);
    res.status(500).json({
        statusCode: 500,
        error: 'Internal Server Error.',
        message: 'An error is occurred while processing the request.',
    });
}
});

                // API to login a user

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

                // Check if the user exists

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({
        statusCode: 401,
        message: 'Invalid email or password.',
      });
    }

                // Check if the password is correct

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({
        statusCode: 401,
        message: 'Invalid email or password.',
      });
    }

                // Generate a JWT token

    const token = jwt.sign({ userId: user._id }, 'secretkey', {
      expiresIn: '24h',
    });    

     return res.status(200).json({
      statusCode: 200,
      data: {
        token,
      },
      message: 'The user is logged in successfully.',
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      statusCode: 500,
      error: 'Internal Server Error.',
      message: 'An error is occurred while processing the request.',
    });
  }
});

// Middleware to authenticate requests
const authenticateUser = (req, res, next) => {
  try {
    const token = req.headers.authorization.split(' ')[1];
    const decodedToken = jwt.verify(token, 'secretkey');
    req.userId = decodedToken.userId;
    next();
  } catch (error) {
    console.error(error);
    res.status(401).json({
      statusCode: 401,
      error: 'Unauthorized!',
      message: 'Authentication failed.',
    });
  }
};

// API to create an article
app.post('/api/users/:userId/articles', authenticateUser, async (req, res) => {
  try {
    const { userId } = req.params;
    const { title, description } = req.body;

    // Check if the user exists
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        statusCode: 404,
        error: 'Not Found!',
        message: 'The user is not found.',
      });
    }

    // Create a new article
    const newArticle = new Article({
      title,
      description,
      author: user._id,
    });
    await newArticle.save();

    res.status(201).json({
      statusCode: 201,
      data: {
        data: newArticle,
      },
      message: 'An article is created successfully.',
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      statusCode: 500,
      error: 'Internal Server Error!',
      message: 'An error occurred while processing the request.',
    });
  }
});

// API to get all articles
app.get('/api/articles', authenticateUser, async (req, res) => {
  try {
    // Find all articles and populate the author information
    const articles = await Article.find().populate('author', 'name age');

    res.status(200).json({
      statusCode: 200,
      data: {
        data: articles,
      },
      message: 'Articles retrieved successfully.',
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      statusCode: 500,
      error: 'Internal Server Error.',
      message: 'An error is occurred while processing the request.',
    });
  }
});

// API to update user profile
app.patch('/api/user/:userId', authenticateUser, async (req, res) => {
  try {
    const { userId } = req.params;
    const { name, age } = req.body;

    // Check if the user exists
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        statusCode: 404,
        error: 'Not Found',
        message: 'The user is not found.',
      });
    }

    // Update the user's name and age
    user.name = name;
    user.age = age;
    await user.save();

    res.status(200).json({
      statusCode: 200,
      data: {
        data: user,
      },
      message: 'The user profile is updated successfully.',
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      statusCode: 500,
      error: 'Internal Server Error.',
      message: 'An error is occurred while processing the request.',
    });
  }
});

// Start the server
app.listen(3000, () => {
  console.log('Server listening on port 3000....');
});
