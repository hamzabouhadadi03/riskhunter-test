import mongoose from 'mongoose';

const connectDB = async () => {
  const MONGO_URI = process.env.MONGO_URI as string;
  if (!MONGO_URI) {
    console.error('MONGO_URI is not defined in environment variables');
    process.exit(1);
  }
  try {
    await mongoose.connect(MONGO_URI);
    console.log('Connected to MongoDB');
  } catch (err) {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  }
};

export default connectDB;