import dotenv from 'dotenv';
import express, { Request, Response } from 'express';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import mongoose, { Schema, Document } from 'mongoose';

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
async function main() {
  try{
      await mongoose.connect(process.env.DATABASE_URL as string);
  }
  catch(err){
      console.log(err);
  }
  
}

// Define the User Interface
interface IUser extends Document {
  username: string;
  email: string;
  password: string;
  role: string;
}

// Define the User Schema
const userSchema = new Schema<IUser>({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' },
});

// Create the User Model
const User = mongoose.model<IUser>('User', userSchema);

// User Registration
app.post('/api/v1/register', async (req: Request, res: Response) => {
  const { username, email, password } = req.body;

  try {
    // Check if email already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User already exists!',
      });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user document
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
    });

    // Save the user to the database
    await newUser.save();

    res.status(201).json({
      success: true,
      message: 'User registered successfully!',
    });
  } catch (error: any) {
    res.status(500).json({
      success: false,
      message: 'Internal server error!',
      error: error.message,
    });
  }
});

// User Login
app.post('/api/v1/login', async (req: Request, res: Response) => {
  const { email, password } = req.body;

  try {
    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    // Compare hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { email: user.email, role: user.role },
      process.env.JWT_SECRET as string,
      {
        expiresIn: process.env.EXPIRES_IN,
      }
    );

    res.json({
      success: true,
      message: 'User successfully logged in!',
      accessToken: token,
    });
  } catch (error: any) {
    res.status(500).json({
      success: false,
      message: 'Internal server error!',
      error: error.message,
    });
  }
});

// Test route
app.get('/', (req: Request, res: Response) => {
  const serverStatus = {
    message: 'Server is running smoothly',
    timestamp: new Date(),
  };
  res.json(serverStatus);
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
