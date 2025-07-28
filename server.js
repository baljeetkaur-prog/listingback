const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const slugify = require('slugify');
const bcrypt = require('bcrypt');
const csv = require('csvtojson');
const XLSX = require('xlsx');
require('dotenv').config();
const app = express();
const PORT = 9000;
const crypto = require('crypto');
const SECRET_KEY = Buffer.from(process.env.AES_SECRET_KEY || 'u7%f@9KxZ1qR#3WmD5gL$2t8BvNpE!Aa', 'utf-8');
const OTP_SECRET_KEY = 'u7%f@9KxZ1qR#3WmD5gL$2t8BvNpE!Aa'; 
const { decryptaes } = require('./security/decryption');
const { v4: uuidv4 } = require('uuid');
const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const seller = await Seller.findById(decoded.id);
    if (!seller) {
      return res.status(401).json({ error: 'Seller not found' });
    }

    req.seller = seller;
    next();
  } catch (err) {
    console.error(err);
    res.status(401).json({ error: 'Token failed' });
  }
};
const userAuthMiddleware = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  let token = authHeader.split(' ')[1];

  try {
    // Check if token is in encrypted JSON format
    if (token.startsWith('{')) {
      const parsed = JSON.parse(token);
      if (!parsed.payload || !parsed.iv) {
        return res.status(400).json({ error: 'Invalid encrypted token structure' });
      }

      token = decryptaes(parsed.payload, parsed.iv);

      if (!token) {
        return res.status(400).json({ error: 'Token decryption failed' });
      }
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    req.user = user;
    next();
  } catch (err) {
    console.error('🔒 Token error:', err.message);
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};
const encryptaes = (data) => {
  const iv = crypto.randomBytes(16); // 16 bytes for AES-CBC
  const cipher = crypto.createCipheriv('aes-256-cbc', SECRET_KEY, iv);
  let encrypted = cipher.update(data, 'utf-8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);

  return {
    payload: encrypted.toString('base64'),
    iv: iv.toString('base64')
  };
};

// Helper function to encrypt OTP with AES-256-CBC
function encryptOtp(otp) {
  if (!OTP_SECRET_KEY || OTP_SECRET_KEY.length !== 32) {
    throw new Error("OTP_SECRET_KEY must be 32 characters long");
  }

  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(OTP_SECRET_KEY), iv);
  let encrypted = cipher.update(otp, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);

  return {
    otp: encrypted.toString('base64'),
    iv: iv.toString('base64')
  };
}

const adminAuth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const uploadDir = path.join(__dirname, 'uploads');

app.use(cors());
app.use(express.json());  


app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}
const categoryStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    const categoryPath = path.join(uploadDir, 'categories');
    if (!fs.existsSync(categoryPath)) {
      fs.mkdirSync(categoryPath, { recursive: true });
    }
    cb(null, categoryPath);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  },
});
const uploadCategory = multer({ storage: categoryStorage });
const subCategoryStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    const subCategoryPath = path.join(uploadDir, 'subcategories'); 
    if (!fs.existsSync(subCategoryPath)) {
      fs.mkdirSync(subCategoryPath, { recursive: true });
    }
    cb(null, subCategoryPath);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname); 
  },
});

const uploadSubCategory = multer({ storage: subCategoryStorage });


// For product images
const productStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    const productPath = path.join(uploadDir, 'products');
    if (!fs.existsSync(productPath)) {
      fs.mkdirSync(productPath, { recursive: true });
    }
    cb(null, productPath);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  },
});
const uploadProduct = multer({ storage: productStorage });
const resumeStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    const resumePath = path.join(uploadDir, 'resumes');

    // Create folder if not exists
    if (!fs.existsSync(resumePath)) {
      fs.mkdirSync(resumePath, { recursive: true });
    }

    cb(null, resumePath);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  },
});
const uploadResume = multer({ storage: resumeStorage });


mongoose.connect('mongodb+srv://baljeetkor6:NhoYMNLXxKYBVJFY@cluster0.9zpt6hi.mongodb.net/listing?retryWrites=true&w=majority&appName=clustor0')
  .then(() => console.log('MongoDB Connected'))
  .catch((e) => console.log("Unable to connect to MongoDB: " + e.message));

const userSchema = new mongoose.Schema({
  phone: { type: String, unique: true, required: true },
   isBlocked: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const otpSchema = new mongoose.Schema({
  phone: String,
  otp: String,
  createdAt: { type: Date, default: Date.now, expires: 300 } // 5 minutes expiry
});

const User = mongoose.model('User', userSchema);
const Otp = mongoose.model('Otp', otpSchema);
app.post('/api/auth/send-otp', async (req, res) => {
  const { payload, iv } = req.body;

  const phone = decryptaes(payload, iv);
  if (!phone || !/^[6-9]\d{9}$/.test(phone)) {
    return res.status(400).json({ error: 'Invalid decrypted phone number' });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  try {
    await Otp.deleteMany({ phone });
    await Otp.create({ phone, otp });

    // 🔐 Encrypt OTP before sending
    const { otp: encryptedOtp, iv: otpIv } = encryptOtp(otp);

    res.status(200).json({
      message: 'OTP sent successfully',
      otp: encryptedOtp,
      otpIv
    });
  } catch (error) {
    console.error('OTP send error:', error.message);
    res.status(500).json({ error: 'Failed to generate OTP' });
  }
});





/**
 * Verify OTP
 */
app.post('/api/auth/verify-otp', async (req, res) => {
  const { payload, iv } = req.body;

  if (!payload || !iv) {
    return res.status(400).json({ error: 'Encrypted data required' });
  }

  let decryptedData;
  try {
    decryptedData = decryptaes(payload, iv); // should return JSON string
    decryptedData = JSON.parse(decryptedData); // convert to object
  } catch (err) {
    return res.status(400).json({ error: 'Failed to decrypt data' });
  }

  const { phone, otp } = decryptedData;

  if (!phone || !otp) {
    return res.status(400).json({ error: 'Missing phone or OTP' });
  }

  try {
    const record = await Otp.findOne({ phone, otp });

    if (!record) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    let user = await User.findOne({ phone });

    if (user && user.isBlocked) {
      return res.status(403).json({ error: 'Your account has been blocked by the admin.' });
    }

    if (!user) {
      user = await User.create({ phone });
    }

    const token = jwt.sign(
      { userId: user._id, phone },
      process.env.JWT_SECRET || 'devsecret123',
      { expiresIn: '7d' }
    );

    await Otp.deleteMany({ phone });

    res.status(200).json({ message: 'Login successful', token });
  } catch (error) {
    console.error('OTP verify error:', error.message);
    res.status(500).json({ error: 'Verification failed' });
  }
});


app.post('/api/auth/check-user', async (req, res) => {
  const { payload, iv } = req.body;
  const phone = decryptaes(payload, iv);

  if (!phone || !/^[6-9]\d{9}$/.test(phone)) {
    return res.status(400).json({ error: 'Invalid decrypted phone number' });
  }

  try {
    const user = await User.findOne({ phone });
    res.status(200).json({ exists: !!user });
  } catch (err) {
    console.error('User check error:', err.message);
    res.status(500).json({ error: 'Error checking user' });
  }
});
app.post('/api/auth/login-phone', async (req, res) => {
  const { payload, iv } = req.body;
  const phone = decryptaes(payload, iv);

  if (!phone || !/^[6-9]\d{9}$/.test(phone)) {
    return res.status(400).json({ error: 'Invalid decrypted phone number' });
  }

  try {
    const user = await User.findOne({ phone });
    if (!user) return res.status(404).json({ error: 'User not registered' });

    if (user.isBlocked) {
      return res.status(403).json({ error: 'Your account has been blocked by the admin.' });
    }

    const token = jwt.sign(
      { userId: user._id, phone },
      process.env.JWT_SECRET || 'devsecret123',
      { expiresIn: '7d' }
    );

    // 🔐 Encrypt token before sending it to frontend
    const { payload: tokenEncrypted, iv: tokenIv } = encryptaes(token);

    res.status(200).json({
      message: 'Login successful',
      token: tokenEncrypted,
      tokenIv: tokenIv
    });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.delete('/api/user/delete/:phone', async (req, res) => {
  const { phone } = req.params;

  try {
    const user = await User.findOne({ phone });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // Delete the user
    await User.deleteOne({ phone });

    // Optional: delete user orders or other related data
    // await Order.deleteMany({ userPhone: phone });

    res.json({ success: true, message: "Account deleted successfully" });
  } catch (err) {
    console.error("Error deleting user:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});


const categorySchema = new mongoose.Schema({
  name: String,
  image: String,
  featured: { type: Boolean, default: false }, 
   commissionPercentage: { type: Number, required: true, default:10 },
  gstPercentage: { type: Number, required: true,default: 5 }
});
const Category = mongoose.model('Category', categorySchema);
app.post('/api/categories', uploadCategory.single('image'), async (req, res) => {
  try {
    const category = new Category({
      name: req.body.name,
      image: req.file ? `/uploads/categories/${req.file.filename}` : '',
      featured: req.body.featured === 'true'
    });
    await category.save();
    res.status(201).json(category);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.get('/api/featured-categories', async (req, res) => {
  try {
    const featured = await Category.find({ featured: true });
    res.status(200).json(featured);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.put('/api/categories/:id', async (req, res) => {
  try {
    const updated = await Category.findByIdAndUpdate(
      req.params.id,
      { featured: req.body.featured === 'true' },
      { new: true }
    );
    res.status(200).json(updated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.get('/api/categories', async (req, res) => {
  try {
    const categories = await Category.find();
    res.json(categories);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.get('/api/categories/:name', async (req, res) => {
  try {
    const category = await Category.findOne({ name: req.params.name });
    if (!category) return res.status(404).json({ error: "Category not found" });

    const products = await Product.find({ category: category._id });
    res.json({ category, products });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.get('/api/categories/by-id/:id', async (req, res) => {
  try {
    const category = await Category.findById(req.params.id);
    if (!category) return res.status(404).json({ message: 'Category not found' });

    res.json({ name: category.name });
  } catch (err) {
    res.status(500).json({ message: 'Server error while fetching category' });
  }
});
const subCategorySchema = new mongoose.Schema({
  name: String,
  category: { type: mongoose.Schema.Types.ObjectId, ref: 'Category' }, 
  types: [String], 
  featured:{type: Boolean, default:false}, 
  image:{type:String, default:""}
});
const SubCategory = mongoose.model('SubCategory', subCategorySchema);
app.post('/api/subcategories', uploadSubCategory.single('image'), async (req, res) => {
  try {
    const { name, categoryId, types, featured } = req.body;

    const subCategory = new SubCategory({
      name,
      category: categoryId,
      types: JSON.parse(types),  // Pass as '["Anarkali", "Straight"]' from frontend/Postman
      featured: featured === 'true',
      image: req.file ? `/uploads/subcategories/${req.file.filename}` : ''
    });

    await subCategory.save();
    res.status(201).json({ message: 'SubCategory created with types', subCategory });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.get('/api/subcategories/:categoryId', async (req, res) => {
  try {
    const subcategories = await SubCategory.find({ category: req.params.categoryId });
    res.status(200).json(subcategories);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.get('/api/featured-subcategories', async (req, res) => {
  try {
    const subcategories = await SubCategory.find({ featured: true });
    res.status(200).json(subcategories);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.get('/api/subcategory/by-id/:id', async (req, res) => {
  try {
    const objectId = new mongoose.Types.ObjectId(req.params.id);

    const subcategory = await SubCategory.findOne({ _id: objectId }).populate('category');

    if (!subcategory) {
      return res.status(404).json({ message: 'Subcategory not found' });
    }

    res.json({
      name: subcategory.name,
      categoryName: subcategory.category?.name || ''
    });
  } catch (error) {
    console.error('Error fetching subcategory:', error.message);
    res.status(500).json({ message: 'Server error' });
  }
});
app.get('/api/subcategories', async (req, res) => {
  try {
    const subcategories = await SubCategory.find().populate('category', 'name');
    res.json(subcategories);
  } catch (error) {
    console.error('Error fetching subcategories:', error);
    res.status(500).json({ error: 'Failed to fetch subcategories' });
  }
});
app.get('/test-sub', async (req, res) => {
  const sub = await SubCategory.findOne().populate('category');
  res.json(sub);
});

app.get('/api/category-tree', async (req, res) => {
  try {
    const categories = await Category.find();
    const categoryTree = [];

    for (const cat of categories) {
      const subcategories = await SubCategory.find({ category: cat._id });

      categoryTree.push({
        _id: cat._id,
        name: cat.name,
        subcategories: subcategories.map(sub => ({
          _id: sub._id,
          name: sub.name,
          types: sub.types
        }))
      });
    }

    res.status(200).json(categoryTree);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.get('/api/subcategory/by-name/:name', async (req, res) => {
  try {
    const subcategory = await SubCategory.findOne({ name: req.params.name }).populate('category');
    
    if (!subcategory) {
      return res.status(404).json({ message: 'Subcategory not found' });
    }

    res.json({
      _id: subcategory._id,
      name: subcategory.name,
      categoryName: subcategory.category?.name || ''
    });
  } catch (error) {
    console.error('Error fetching subcategory by name:', error.message);
    res.status(500).json({ message: 'Server error' });
  }
});
const sellerSchema = new mongoose.Schema({
  // Basic Identity
  gstin: {
    type: String,
    unique: true,
    sparse: true,
    match: /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$/,
  },
  enrollmentId: {
    type: String,
    unique: true,
    sparse: true,
    match: /^[A-Z0-9]{15}$/,
  },

  // Future: Seller’s user account (optional if integrated with User model)
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
  },

  // Pickup Address
  pickupAddress: {
    fullName: String,
    phone: String,
    pincode: String,
    addressLine: String,
    city: String,
    state: String,
  },

  // Bank Details
  bankDetails: {
    accountHolderName: String,
    accountNumber: String,
    ifscCode: String,
    bankName: String,
    branch: String,
  },

  // Supplier Details
  companyName: String,
   email: {
    type: String,
    unique: true,
    sparse: true,
    lowercase: true,
    trim: true,

  },
  phone: String,
  password: {type:String, required:false,minlength:6},

  usertype: {
    type: String,
    default: 'seller',
    enum: ['seller']
  },

  // Status Flags
  isGstVerified: { type: Boolean, default: false },
  isEnrolmentVerified: { type: Boolean, default: false },
  isPickupAdded: { type: Boolean, default: false },
  isBankDetailsAdded: { type: Boolean, default: false },
  isApprovedSeller: { type: Boolean, default: false },
   isBlocked: { type: Boolean, default: false },

  // Timestamp
  createdAt: { type: Date, default: Date.now },
});
const Seller=mongoose.model('Seller',sellerSchema,'Seller')


// POST /api/seller/verify
app.post('/api/sellerverify', async (req, res) => {
  try {
    let { gstin, enrollmentId } = req.body;

    gstin = gstin?.trim();
    enrollmentId = enrollmentId?.trim();

    if (!gstin && !enrollmentId) {
      return res.status(400).json({ error: 'Please provide GSTIN or Enrolment ID.' });
    }

    const gstRegex = /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$/;
    const enrollRegex = /^[A-Z0-9]{15}$/;

    if (gstin && !gstRegex.test(gstin)) {
      return res.status(400).json({ error: 'Invalid GSTIN format.' });
    }
    if (enrollmentId && !enrollRegex.test(enrollmentId)) {
      return res.status(400).json({ error: 'Invalid Enrolment ID format.' });
    }

    const existing = await Seller.findOne({
      $or: [
        gstin ? { gstin } : null,
        enrollmentId ? { enrollmentId } : null
      ].filter(Boolean)
    });

    if (existing) {
      return res.status(409).json({ error: 'This GSTIN or Enrolment ID is already registered.' });
    }

    const newSeller = new Seller({
      gstin: gstin || undefined,
      enrollmentId: enrollmentId || undefined,
      isGstVerified: !!gstin,
      isEnrolmentVerified: !!enrollmentId,
    });

    await newSeller.save();
    return res.status(201).json({ message: 'Verification successful.', sellerId: newSeller._id });

  } catch (error) {
    console.error('Verification error:', error);
    return res.status(500).json({ error: 'Server error. Please try again later.' });
  }
});


// Update Pickup Address
app.put('/api/seller/pickup-address/:id', async (req, res) => {
  const { id } = req.params;
  const {
    fullName,
    phone,
    pincode,
    addressLine,
    city,
    state,
  } = req.body;

  // Basic Validation
  if (!fullName || !phone || !pincode || !addressLine || !city || !state) {
    return res.status(400).json({ error: 'All fields are required.' });
  }
      if (!/^\d{6}$/.test(pincode)) {
  return res.status(400).json({ error: 'Invalid pincode format.' });
}

if (!/^\d{10}$/.test(phone)) {
  return res.status(400).json({ error: 'Invalid phone number format.' });
}

  try {
    const updatedSeller = await Seller.findByIdAndUpdate(
      id,
      {
        pickupAddress: { fullName, phone, pincode, addressLine, city, state },
        isPickupAdded: true,
      },
      { new: true }
    );

    if (!updatedSeller) {
      return res.status(404).json({ error: 'Seller not found.' });
    }

    res.status(200).json({ message: 'Pickup address updated successfully.' });
  } catch (error) {
    console.error('Error updating pickup address:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
});
app.put('/api/seller/bank-details/:sellerId', async (req, res) => {
  try {
    const { sellerId } = req.params;
    const { accountHolderName, accountNumber, ifscCode, bankName, branch } = req.body;

    // Validate required fields
    if (!accountHolderName || !accountNumber || !ifscCode || !bankName || !branch) {
      return res.status(400).json({ error: 'All bank details are required.' });
    }

    // Validate IFSC code format
    const ifscRegex = /^[A-Z]{4}0[A-Z0-9]{6}$/;
    if (!ifscRegex.test(ifscCode)) {
      return res.status(400).json({ error: 'Invalid IFSC Code format.' });
    }

    // Update seller document
    const updatedSeller = await Seller.findByIdAndUpdate(
      sellerId,
      {
        bankDetails: {
          accountHolderName,
          accountNumber,
          ifscCode,
          bankName,
          branch,
        },
        isBankDetailsAdded: true,
      },
      { new: true }
    );

    if (!updatedSeller) {
      return res.status(404).json({ error: 'Seller not found.' });
    }

    res.json({ message: 'Bank details saved successfully.' });
  } catch (error) {
    console.error('Bank details update error:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
});
app.put('/api/seller/supplier-details/:sellerId', async (req, res) => {
  try {
    const { sellerId } = req.params;
    const { companyName, email, phone, password } = req.body;

    // Validate required fields
    if (!companyName || !email || !phone || !password) {
      return res.status(400).json({ error: 'All fields are required.' });
    }

    // Check if email already exists for another seller
    const emailExists = await Seller.findOne({ email, _id: { $ne: sellerId } });
    if (emailExists) {
      return res.status(409).json({ error: 'Email already in use.' });
    }

    // Hash password using bcrypt
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update seller
    const updatedSeller = await Seller.findByIdAndUpdate(
      sellerId,
      {
        companyName,
        email,
        phone,
        password: hashedPassword,
      },
      { new: true }
    );

    if (!updatedSeller) {
      return res.status(404).json({ error: 'Seller not found.' });
    }

    res.json({ message: 'Supplier details saved successfully.' });
  } catch (err) {
    console.error('Supplier details error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});
app.post('/api/seller/login', async (req, res) => {
  let { email, password } = req.body;

  // ✅ Decode base64
  try {
    email = decodeURIComponent(escape(Buffer.from(email, 'base64').toString()));
    password = decodeURIComponent(escape(Buffer.from(password, 'base64').toString()));
  } catch (e) {
    return res.status(400).json({ error: 'Invalid payload format' });
  }

  const seller = await Seller.findOne({ email });
  if (!seller) {
    return res.status(404).json({ error: 'Seller not found. Please register first.' });
  }

  const isPasswordMatch = await bcrypt.compare(password, seller.password);
  if (!isPasswordMatch) {
    return res.status(401).json({ error: 'Invalid password' });
  }

  const token = jwt.sign({ id: seller._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

  // ✅ Encrypt the whole response (seller, token, message)
  const { payload, iv } = encryptaes(
    JSON.stringify({ seller, token, message: 'Login successful' })
  );

  return res.status(200).json({ payload, iv });
});

app.put('/api/schange-password', authMiddleware, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Both current and new password are required.' });
  }

  try {
    const seller = await Seller.findById(req.seller.id); // `req.seller.id` should come from auth middleware

    if (!seller) {
      return res.status(404).json({ error: 'Seller not found.' });
    }

    // Compare current password
    const isMatch = await bcrypt.compare(currentPassword, seller.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Current password is incorrect.' });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedNewPassword = await bcrypt.hash(newPassword, salt);

    seller.password = hashedNewPassword;
    await seller.save();

    res.json({ message: 'Password updated successfully.' });
  } catch (err) {
    console.error('Change Password Error:', err);
    res.status(500).json({ error: 'Server error. Please try again.' });
  }
});


app.get('/api/seller/dashboard-stats', authMiddleware, async (req, res) => {
  try {
    const sellerId = req.seller._id;
    const seller = await Seller.findById(sellerId);

    // Products & stock
    const products = await Product.find({ seller: sellerId });
    const productCount = products.length;
    const lowStockCount = products.filter(p => p.stock <= 5).length;

    // Orders where this seller has at least one product
    const orders = await Order.find({ "products.sellerId": sellerId });

    // Earnings summary
    let totalSales = 0;
    let totalCommission = 0;
    let totalGST = 0;
    let totalNetPayout = 0;

   orders.forEach(order => {
  // Filter products that belong to this seller
  const sellerProducts = order.products.filter(
    prod => prod.sellerId?.toString() === sellerId.toString()
  );

  if (sellerProducts.length > 0) {
    const totalOrderProductValue = order.products.reduce(
      (sum, prod) => sum + prod.price * prod.quantity,
      0
    );

    const sellerProductValue = sellerProducts.reduce(
      (sum, prod) => sum + prod.price * prod.quantity,
      0
    );

    // Calculate seller's share of final amount (after discount)
    const sellerFinalAmount = order.finalAmount * (sellerProductValue / totalOrderProductValue);

    totalSales += sellerFinalAmount;

    // Sum individual commission, GST, payout
    sellerProducts.forEach(prod => {
      totalCommission += prod.commissionAmount || 0;
      totalGST += prod.gstAmount || 0;
      totalNetPayout += prod.netPayoutToSeller || 0;
    });
  }
});


    res.json({
      sellerName: seller.companyName,
      products: productCount,
      orders: orders.length,
      sales: totalSales,
      commission: totalCommission,
      gst: totalGST,
      netPayable: totalNetPayout,
      finalAmount: totalNetPayout,
      lowStock: lowStockCount
    });
  } catch (err) {
    console.error('Dashboard stats error:', err);
    res.status(500).json({ error: 'Failed to load dashboard stats' });
  }
});

app.get('/api/seller/earnings', authMiddleware, async (req, res) => {
  try {
    const sellerId = req.seller._id;
    
    // Fetch all orders containing this seller's products
    const orders = await Order.find({ 'products.sellerId': sellerId });

    const earningsList = [];

    for (const order of orders) {
      for (const prod of order.products) {
        if (prod.sellerId?.toString() === sellerId.toString()) {

          // 🔍 Get product to fetch category info
          const product = await Product.findById(prod.productId).lean();
          
          let commissionPercentage = 0;
          let gstPercentage = 0;

          if (product?.category) {
            const category = await Category.findById(product.category).lean();
            if (category) {
              commissionPercentage = category.commissionPercentage || 0;
              gstPercentage = category.gstPercentage || 0;
            }
          }

          // ✅ Push entry with additional % data
          earningsList.push({
            productName: prod.name,
            productId: prod.productId,
            orderedAt: order.orderedAt,
            quantity: prod.quantity,
            commissionAmount: prod.commissionAmount || 0,
            gstAmount: prod.gstAmount || 0,
            netPayoutToSeller: prod.netPayoutToSeller || 0,
            grossSale: prod.price * prod.quantity,
            commissionPercentage,
            gstPercentage
          });
        }
      }
    }

    res.json(earningsList);
  } catch (err) {
    console.error('Error fetching seller earnings:', err);
    res.status(500).json({ error: 'Server Error: Could not fetch earnings' });
  }
});

app.put('/api/seller/products/:id/stock', authMiddleware, async (req, res) => {
  const { stock } = req.body;
  if (stock < 0) return res.status(400).json({ error: 'Invalid stock' });

  try {
    await Product.findByIdAndUpdate(req.params.id, { stock });
    res.json({ message: 'Stock updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update stock' });
  }
});
app.get('/api/smonthly-performance', authMiddleware, async (req, res) => {
  try {
    const sellerId = new mongoose.Types.ObjectId(req.seller._id); // seller's ID from token

    const stats = await Order.aggregate([
      { $unwind: "$products" }, // flatten products array
      { $match: { "products.sellerId": sellerId } },
      {
        $group: {
          _id: {
            month: { $month: "$orderedAt" }
          },
          orders: { $addToSet: "$_id" }, // Unique orders
          sales: { $sum: "$finalAmount" },
          earnings: { $sum: "$products.netPayoutToSeller" },
          sold: { $sum: "$products.quantity" }
        }
      },
      {
        $project: {
          month: {
            $let: {
              vars: {
                months: ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
              },
              in: { $arrayElemAt: ["$$months", "$_id.month"] }
            }
          },
          orders: { $size: "$orders" },
          sales: 1,
          earnings: 1,
          sold: 1
        }
      },
      { $sort: { month: 1 } }
    ]);

    res.json(stats);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Failed to load monthly performance' });
  }
});


// app.get('/api/seller/products', async (req, res) => {
//   try {

//     const products = await Product.find().populate('category','name').populate('subcategory','name').sort({createdAt:-1}); 
     

//     res.status(200).json(products);
//   } catch (err) {
//     console.error('Error fetching seller products:', err);
//     res.status(500).json({ error: 'Server error' });
//   }
// });
const brandTagSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  categoryId: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', default: null },
  subcategoryId: { type: mongoose.Schema.Types.ObjectId, ref: 'SubCategory', default: null },
  type: { type: String, default: null },
});
const Brand= mongoose.model('Brand', brandTagSchema);
app.get('/api/brand-tag/:name', async (req, res) => {
  try {
    const tag = await Brand.findOne({ name: req.params.name });
    if (!tag) return res.status(404).json({ message: 'Brand tag not found' });
    res.json(tag);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});
const ratingSchema = new mongoose.Schema({
  userPhone: { type: String, required: true },
  stars: { type: Number, required: true },
  review: { type: String },
  ratedAt: { type: Date, default: Date.now }
}, { _id: false }); // Optional: disable _id for subdocs

const productSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true },
  slug: { type: String, unique: true, lowercase: true },
  description: { type: String, default: '' },
  category: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', required: true },
  subcategory: { type: mongoose.Schema.Types.ObjectId, ref: 'SubCategory', required: true },
  type: { type: String, required: true },
   sizes: { type: [String], default: ['Free Size'] },
  colors: [String],
  price: { type: Number, required: true },
  discountPrice: { type: Number },
  stock: { type: Number, default: 1 },
  gender: { type: String, enum: ['men', 'women', 'kids', 'unisex'], default: 'unisex' },
 images: [String],

  thumbnail: { type: String },
  tags: [String],
  brand: { type: String, default: 'No Brand' },
  specifications: { type: Map, of: String },
 ratings: [ratingSchema],
averageRating: { type: Number, default: 0 },
  isFeatured: { type: Boolean, default: false },
  isTrending: { type: Boolean, default: false }, 
  commissionRate: { type: Number, default: 10 },
  gstRate: { type: Number, default: 5 }, 
   seller: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Seller',
    required: true
  }
}, {
  timestamps: true // ✅ This enables `createdAt` and `updatedAt`
});


const Product = mongoose.model('Product', productSchema);
app.post(
  '/api/products',
  authMiddleware,
  uploadProduct.fields([
    { name: 'images', maxCount: 5 },
    { name: 'thumbnail', maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const {
        title,
        description,
        category,
        subcategory,
        type,
        sizes,
        colors,
        price,
        discountPrice,
        stock,
        gender,
        tags,
        brand,
        specifications,
        isFeatured,
        isTrending
      } = req.body;

      if (!title || !category || !subcategory || !type || !price) {
        return res.status(400).json({ error: 'Missing required fields' });
      }

      // ✅ Fetch category to get commission and GST
      const categoryDoc = await Category.findById(category);
      if (!categoryDoc) {
        return res.status(404).json({ error: 'Invalid category selected' });
      }

      const imageFiles = req.files['images'] || [];
      const thumbnailFile = req.files['thumbnail']?.[0];

      if (imageFiles.length > 5) {
        return res.status(400).json({ error: 'You can upload a maximum of 5 product images' });
      }
      if (req.files['thumbnail'] && req.files['thumbnail'].length > 1) {
        return res.status(400).json({ error: 'Only one thumbnail image is allowed' });
      }

      const imagePaths = imageFiles.map(file => `/uploads/products/${file.filename}`);
      const thumbnailPath = thumbnailFile ? `/uploads/products/${thumbnailFile.filename}` : '';

      const baseSlug = slugify(title, { lower: true });
      const existing = await Product.findOne({ slug: baseSlug });
      const uniqueSlug = existing ? `${baseSlug}-${Date.now()}` : baseSlug;

     const product = new Product({
  title,
  slug: uniqueSlug,
  description,
  category,
  subcategory,
  type,
  sizes: sizes ? JSON.parse(sizes) : ['Free Size'], // ✅ updated line
  colors: JSON.parse(colors || '[]'),
  price,
  discountPrice,
  stock,
  gender,
  images: imagePaths,
  thumbnail: thumbnailPath,
  tags: JSON.parse(tags || '[]'),
  brand: brand || 'No Brand',
  specifications: specifications ? JSON.parse(specifications) : {},
  isFeatured: isFeatured === 'true' || isFeatured === true,
  isTrending: isTrending === 'true' || isTrending === true,
  seller: req.seller._id,
  commissionRate: categoryDoc.commissionPercentage,
  gstRate: categoryDoc.gstPercentage
});

      await product.save();

      res.status(201).json({ message: 'Product uploaded successfully', product });
    } catch (error) {
      console.error('Error uploading product:', error);
      res.status(500).json({ error: 'Server error while uploading product' });
    }
  }
);





app.get('/api/products', async (req, res) => {
  try {
    const { gender, categoryId, subcategoryId, type, priceRange, sort } = req.query;
    const filter = {};

    if (gender) filter.gender = gender;

    if (categoryId) {
      const catArr = Array.isArray(categoryId) ? categoryId : [categoryId];
      filter.category = { $in: catArr.map(id => new mongoose.Types.ObjectId(id)) };
    }

    if (subcategoryId) {
      const subArr = Array.isArray(subcategoryId) ? subcategoryId : [subcategoryId];
      filter.subcategory = { $in: subArr.map(id => new mongoose.Types.ObjectId(id)) };
    }

    if (type) filter.type = type;

    if (priceRange) {
      const [min, max] = priceRange.split('-').map(Number);
      filter.price = { $gte: min, $lte: max };
    }

    // ✅ Sort by discount: only products where discountPrice < price
    if (sort === 'discount') {
      const products = await Product.aggregate([
        {
          $match: {
            ...filter,
            $expr: { $lt: ['$discountPrice', '$price'] }
          }
        },
        {
          $addFields: {
            discountValue: { $subtract: ['$price', '$discountPrice'] }
          }
        },
        {
          $sort: { discountValue: -1 } // Highest discount first
        }
      ]);
      return res.status(200).json(products);
    }

    // ✅ All other sorts
    let sortOption = {};
    switch (sort) {
      case 'priceLow':
        sortOption.discountPrice = 1;
        break;
      case 'priceHigh':
        sortOption.discountPrice = -1;
        break;
      case 'new':
        sortOption.createdAt = -1;
        break;
      case 'rating':
        sortOption.averageRating = -1;
        break;
      default:
        sortOption.createdAt = -1;
    }

    const products = await Product.find(filter)
      .populate('seller', 'companyName')
      .sort(sortOption);

    res.status(200).json(products);
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});






app.get('/api/products/:productId', async (req, res) => {
  try {
    const product = await Product.findById(req.params.productId);
    if (!product) return res.status(404).json({ error: 'Product not found' });
    res.json(product);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});
app.get('/api/products/by-id/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id)
      .populate({
        path: 'subcategory',
        populate: { path: 'category' }
      })
      .populate('seller', 'companyName email phone');

    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }

    const plainProduct = product.toObject();

    // ✅ Convert Map to object
    const specifications = {};
    if (product.specifications instanceof Map) {
      for (let [key, value] of product.specifications.entries()) {
        specifications[key] = value;
      }
    }

    let categoryId = '';
    let categoryName = '';
    let subcategoryId = '';
    let subcategoryName = '';

    if (product.subcategory) {
      subcategoryId = product.subcategory._id;
      subcategoryName = product.subcategory.name;
      if (product.subcategory.category) {
        categoryId = product.subcategory.category._id;
        categoryName = product.subcategory.category.name;
      }
    }

    res.status(200).json({
      ...plainProduct,
      specifications, // ✅ force overwrite with plain object
      breadcrumb: {
        categoryId,
        categoryName,
        subcategoryId,
        subcategoryName,
        type: product.type || ''
      }
    });
  } catch (err) {
    console.error('Error fetching product:', err.message);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/products/by-ids', async (req, res) => {
  try {
    const { ids } = req.body;
    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: 'Invalid product IDs' });
    }

    const products = await Product.find({ _id: { $in: ids } });

    // Create a map for quick lookup by id
    const productMap = {};
    products.forEach(p => {
      productMap[p._id.toString()] = p;
    });

    // Reorder products to match the ids order
    const orderedProducts = ids
      .map(id => productMap[id])
      .filter(p => p !== undefined); // Filter out missing products if any

    res.status(200).json(orderedProducts);
  } catch (error) {
    console.error('Error fetching products by IDs:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.put(
  '/api/products/:id',
  authMiddleware,
  uploadProduct.fields([
    { name: 'images', maxCount: 5 },
    { name: 'thumbnail', maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const productId = req.params.id;
       const existingProduct = await Product.findOne({ _id: productId, seller: req.seller._id });
      if (!existingProduct) {
        return res.status(404).json({ error: 'Product not found' });
      }

      const {
        title,
        description,
        category,
        subcategory,
        type,
        sizes,
        colors,
        price,
        discountPrice,
        stock,
        gender,
        tags,
        brand,
        specifications,
        isFeatured,
        isTrending,
      } = req.body;

      // Optional slug update
      if (title && title !== existingProduct.title) {
        const baseSlug = slugify(title, { lower: true });
        const existingSlug = await Product.findOne({ slug: baseSlug });
        existingProduct.slug = existingSlug ? `${baseSlug}-${Date.now()}` : baseSlug;
      }

      // Update other fields
      existingProduct.title = title ?? existingProduct.title;
      existingProduct.description = description ?? existingProduct.description;
      existingProduct.category = category ?? existingProduct.category;
      existingProduct.subcategory = subcategory ?? existingProduct.subcategory;
      existingProduct.type = type ?? existingProduct.type;
      existingProduct.sizes = sizes?.trim()
  ? JSON.parse(sizes)
  : existingProduct.colors;
      existingProduct.colors = colors?.trim()
  ? JSON.parse(colors)
  : existingProduct.colors;
      existingProduct.price = price ?? existingProduct.price;
      existingProduct.discountPrice = discountPrice ?? existingProduct.discountPrice;
      existingProduct.stock = stock ?? existingProduct.stock;
      existingProduct.gender = gender ?? existingProduct.gender;
     existingProduct.tags = tags?.trim()
  ? JSON.parse(tags)
  : existingProduct.colors;
      existingProduct.brand = brand ?? existingProduct.brand;
      existingProduct.specifications = specifications
        ? JSON.parse(specifications)
        : existingProduct.specifications;
      existingProduct.isFeatured = isFeatured ?? existingProduct.isFeatured;
      existingProduct.isTrending = isTrending ?? existingProduct.isTrending;

      // ✅ Optional file updates
      const imageFiles = req.files['images'] || [];
      const thumbnailFile = req.files['thumbnail']?.[0];

      if (imageFiles.length > 0) {
        existingProduct.images = imageFiles.map(file => `/uploads/products/${file.filename}`);
      }

      if (thumbnailFile) {
        existingProduct.thumbnail = `/uploads/products/${thumbnailFile.filename}`;
      }

      await existingProduct.save();
      res.json({ message: 'Product updated successfully', product: existingProduct });
    } catch (error) {
      console.error('Error updating product:', error);
      res.status(500).json({ error: 'Server error while updating product' });
    }
  }
);

app.get('/api/seller/products', authMiddleware, async (req, res) => {
  try {
    const sellerId = req.seller._id;
    const { category, subcategory, type } = req.query;

    const query = { seller: sellerId };

    if (category) query.category = category;
    if (subcategory) query.subcategory = subcategory;
   if (type) {
  query.type = { $regex: new RegExp(`^${type}$`, 'i') }; // case-insensitive exact match
}

    const products = await Product.find(query);
    res.json(products);
  } catch (err) {
    console.error("Error fetching products:", err);
    res.status(500).json({ error: "Failed to fetch seller products" });
  }
});
app.delete('/api/products/:id', authMiddleware, async (req, res) => {
  try {
    const productId = req.params.id;

    // 1. Find the product with seller ownership check
    const product = await Product.findOne({ _id: productId, seller: req.seller._id });
    if (!product) return res.status(404).json({ error: 'Product not found or unauthorized' });

    // 2. Delete thumbnail
    if (product.thumbnail) {
      const thumbRelativePath = product.thumbnail.replace('/uploads/', '');
      const thumbPath = path.join(uploadDir, thumbRelativePath);
      if (fs.existsSync(thumbPath)) {
        fs.unlinkSync(thumbPath);
      }
    }

    // 3. Delete images
    if (Array.isArray(product.images)) {
      for (const img of product.images) {
        const imgRelativePath = img.replace('/uploads/', '');
        const imgPath = path.join(uploadDir, imgRelativePath);
        if (fs.existsSync(imgPath)) {
          fs.unlinkSync(imgPath);
        }
      }
    }

    // 4. Delete the product from DB
    await Product.findByIdAndDelete(productId);

    res.json({ message: 'Product deleted successfully' });

  } catch (error) {
    console.error('Error deleting product:', error);
    res.status(500).json({ error: 'Server error while deleting product' });
  }
});

app.post('/api/products/bulk-upload', authMiddleware, uploadProduct.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const filePath = req.file.path;
    const sellerId = req.seller._id;
    const allowedGenders = ['men', 'women', 'kids', 'unisex'];
    const ext = path.extname(filePath).toLowerCase();

    let products = [];

    if (ext === '.csv') {
      products = await csv().fromFile(filePath);
    } else if (ext === '.xlsx' || ext === '.xls') {
      const workbook = XLSX.readFile(filePath);
      const sheetName = workbook.SheetNames[0];
      const worksheet = workbook.Sheets[sheetName];
      products = XLSX.utils.sheet_to_json(worksheet);
    } else {
      fs.unlinkSync(filePath);
      return res.status(400).json({ error: 'Unsupported file format. Only CSV or Excel files allowed.' });
    }

    const formattedProducts = [];

    for (const p of products) {
      let parsedSpecs = {};
      try {
        parsedSpecs = p.specifications ? JSON.parse(p.specifications) : {};
      } catch (err) {
        console.log('Invalid specifications JSON:', p.specifications);
      }

      const categoryDoc = await Category.findOne({ name: p.category?.trim() });
      const subcategoryDoc = await SubCategory.findOne({ name: p.subcategory?.trim() });

      if (!categoryDoc || !subcategoryDoc) {
        fs.unlinkSync(filePath);
        return res.status(400).json({
          error: `Invalid category or subcategory for product: ${p.title}`,
        });
      }

      const rawGender = (p.gender || 'unisex').toLowerCase();
      const validGender = allowedGenders.includes(rawGender) ? rawGender : 'unisex';

      const title = p.title?.trim() || 'product';
      const generatedSlug = slugify(`${title}-${Date.now()}-${Math.floor(Math.random() * 1000)}`, {
        lower: true,
        strict: true,
      });

      formattedProducts.push({
        seller: sellerId,
        title: title,
        slug: generatedSlug,
        description: p.description || '',
        category: categoryDoc._id,
        subcategory: subcategoryDoc._id,
        type: p.type || '',
        sizes: p.sizes ? p.sizes.split(',').map(s => s.trim()) : [],
        colors: p.colors ? p.colors.split(',').map(c => c.trim()) : [],
        price: Number(p.price),
        discountPrice: p.discountPrice ? Number(p.discountPrice) : undefined,
        stock: Number(p.stock) || 1,
        gender: validGender,
        tags: p.tags ? p.tags.split(',').map(t => t.trim()) : [],
        brand: p.brand || '',
        specifications: parsedSpecs,
        isFeatured: p.isFeatured === 'true',
        isTrending: p.isTrending === 'true',
        thumbnail: p.thumbnail || '',
        images: p.images
          ? p.images.split(',').map(img => img.trim()).filter(img => img.length > 0)
          : [],
      });
    }

    await Product.insertMany(formattedProducts);
    fs.unlinkSync(filePath);

    res.status(200).json({ message: 'Bulk products uploaded successfully.' });

  } catch (error) {
    console.error('Bulk upload error:', error);
    if (req.file?.path && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({ error: 'Failed to upload bulk products.' });
  }
});
app.get('/api/seller/product-detail', authMiddleware, async (req, res) => {
  try {
    const { productId } = req.query;
    const sellerId = req.seller._id;

    if (!productId) {
      return res.status(400).json({ error: 'Product ID is required' });
    }

    const product = await Product.findOne({ _id: productId, seller: sellerId })
      .populate('category', 'name')
      .populate('subcategory', 'name')
     .populate('seller', 'companyName')

    if (!product) {
      return res.status(404).json({ error: 'Product not found or unauthorized' });
    }

    res.json(product);
  } catch (err) {
    console.error('Error fetching product detail:', err);
    res.status(500).json({ error: 'Server error' });
  }
});









const cartSchema = new mongoose.Schema({
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
  image: String,
  name: String,
  originalPrice: Number,
  quantity: Number,
  totalcost: Number,
  phone: { type: String, required: true },

  // ✅ Add these two fields:
  size: { type: String },
  color: { type: String }
}, { versionKey: false });

const cartModel = mongoose.model("Cart", cartSchema, "Cart");
app.post('/api/addtocart', async (req, res) => {
  const {
    phone,
    productId,
    name,
    originalPrice,
    quantity,
    image,
    size,         // ✅ from frontend
    color         // ✅ from frontend
  } = req.body;

  if (!phone || !productId || !name || !originalPrice || !quantity) {
    return res.status(400).json({ success: false, message: "Missing required fields" });
  }

  try {
    const totalcost = originalPrice * quantity;

    const existing = await cartModel.findOne({ phone, productId, size, color });

    if (existing) {
      existing.quantity += quantity;
      existing.totalcost = existing.originalPrice * existing.quantity;
      await existing.save();
      return res.json({ success: true, message: "Cart updated", cartItem: existing });
    } else {
      const newItem = new cartModel({
        phone,
        productId,
        name,
        originalPrice,
        quantity,
        totalcost,
        image,
        size,       // ✅ use correct key
        color       // ✅ use correct key
      });
      await newItem.save();
      return res.json({ success: true, message: "Item added to cart", cartItem: newItem });
    }
  } catch (err) {
    console.error("Error adding to cart:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});
app.post('/api/updateCartSelection', async (req, res) => {
  const { productId, phone, size, color } = req.body;

  try {
    const cartItem = await cartModel.findOne({ productId, phone });

    if (!cartItem) {
      return res.status(404).json({ success: false, message: "Cart item not found" });
    }

    if (size) cartItem.size = size;
    if (color) cartItem.color = color;

    await cartItem.save();

    return res.json({ success: true, message: "Cart item updated with size/color" });
  } catch (err) {
    console.error("Error updating cart:", err);
    return res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

app.get('/api/fetchcart/:phone', async (req, res) => {
  const { phone } = req.params;

  if (!phone) {
    return res.status(400).json({ success: false, message: "Phone number is required" });
  }

  try {
    const cartItems = await cartModel.find({ phone }).populate('productId');

    const formattedCart = cartItems.map(item => {
      const product = item.productId;
      const price = product?.price || 0;
      const discountPrice = product?.discountPrice || null;
      const finalPrice = discountPrice || price;

      return {
        _id: item._id,
        productId: product?._id,
        quantity: item.quantity,
        totalcost: item.quantity * finalPrice,
        name: product?.title,
        image: product?.thumbnail || product?.images?.[0]?.url || '/default.jpg',
        price,
        discountPrice,
        discountPercent: discountPrice
          ? Math.round(((price - discountPrice) / price) * 100)
          : 0,
        size: item.size || null,
        color: item.color || null
      };
    });

    // Use your existing encrypt function
    const encrypted = encryptaes(JSON.stringify(formattedCart));

    return res.json(encrypted); // { payload, iv }
  } catch (error) {
    console.error("Error fetching cart:", error);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});



app.delete('/api/removefromcart/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const removed = await cartModel.findByIdAndDelete(id);
    if (!removed) {
      return res.status(404).json({ success: false, message: "Item not found" });
    }
    return res.json({ success: true, message: "Item removed from cart" });
  } catch (err) {
    console.error("Error removing item:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

const addressSchema = new mongoose.Schema({
  phone: { type: String, required: true },
  name: { type: String, required: true },
  houseNo: String,
  roadName: String,
  area: String,
  pincode: String,
  city: String,
  state: String,
  nearby: String,
}, { timestamps: true });

const addressModel = mongoose.model("Address", addressSchema, "Address");

// ✅ Create new address (allow multiple)
app.post('/api/saveaddress', async (req, res) => {
  const { phone, name, houseNo, roadName, area, pincode, city, state, nearby } = req.body;

  if (!phone || !name) {
    return res.status(400).json({ success: false, message: "Missing required fields" });
  }

  try {
    const newAddress = new addressModel({ phone, name, houseNo, roadName, area, pincode, city, state, nearby });
    await newAddress.save();
    return res.json({ success: true, message: "Address saved", address: newAddress });
  } catch (err) {
    console.error("Error saving address:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ✅ Get all addresses for a phone
app.get('/api/getaddress/:phone', async (req, res) => {
  try {
    const phone = req.params.phone;
    const addresses = await addressModel.find({ phone });

    if (addresses.length === 0) {
      return res.status(404).json({ success: false, message: "No addresses found" });
    }

    res.status(200).json({ success: true, addresses });
  } catch (error) {
    console.error("Error fetching addresses:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ✅ Update address by ID
app.put('/api/updateaddress/:id', async (req, res) => {
  try {
    const updated = await addressModel.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!updated) {
      return res.status(404).json({ success: false, message: 'Address not found' });
    }
    res.json({ success: true, address: updated });
  } catch (err) {
    console.error("Error updating address:", err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});
app.delete('/api/clearcart/:phone', async (req, res) => {
  try {
    const phone = req.params.phone;
    await cartModel.deleteMany({ phone });
    res.json({ success: true });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});
app.get("/api/getprodsbyname", async (req, res) => {
  try {
    const { q, categoryId, subcategoryId, gender, priceRange } = req.query;
    const filter = [];
    const subfilter = {};

    const isAnyOtherFilterApplied =
      (categoryId && categoryId.trim() !== "") ||
      (subcategoryId && subcategoryId.trim() !== "") ||
      (gender && gender !== "All") ||
      priceRange;

    if (q && q.trim() !== "" && !isAnyOtherFilterApplied) {
      filter.push({ title: { $regex: '.*' + q + '.*', $options: 'i' } });
    }

    if (categoryId && categoryId.trim() !== "") {
      const ids = categoryId.split(',').filter(id => id.trim() !== '');
      if (ids.length > 0) {
        subfilter.categoryId = { $in: ids };
      }
    }

    if (subcategoryId && subcategoryId.trim() !== "") {
      const subIds = subcategoryId.split(',').filter(id => id.trim() !== '');
      if (subIds.length > 0) {
        subfilter.subcategoryId = { $in: subIds };
      }
    }

    if (gender && gender !== 'All') {
      subfilter.gender = gender;
    }

    if (priceRange) {
      const [min, max] = priceRange.split('-');
      subfilter.price = {
        ...(min && { $gte: parseInt(min) }),
        ...(max && { $lte: parseInt(max) }),
      };
    }

    if (Object.keys(subfilter).length > 0) {
      filter.push(subfilter);
    }


    const result = await Product.find(filter.length > 0 ? { $and: filter } : {});
    res.send({ success: true, pdata: result });
  } catch (e) {
    console.error("❌ Error in getprodsbyname:", e.message);
    res.send({ success: false, errormessage: e.message });
  }
});





app.get('/api/search-suggestions', async (req, res) => {
  const { q } = req.query;
  if (!q) return res.json([]);

  try {
    const suggestions = await Product.find({
      title: { $regex: `^${q}`, $options: 'i' }
    })
      .limit(7)
      .select('title -_id');

    res.json(suggestions.map(s => s.title));
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

const orderSchema = new mongoose.Schema({
  orderId: { type: String, required: true, unique: true },
  userPhone: { type: String, required: true },

  shippingAddress: {
    name: String,
    phone: String,
    houseNo: String,
    roadName: String,
    area: String,
    city: String,
    state: String,
    pincode: String,
    nearby: String
  },

  products: [
    {
      productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
      name: String,
      image: String,
      quantity: Number,
      price: Number,
       size: String,
      color: String,
      sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Seller' }, 
      commissionRate: { type: Number, default: 10 },   
      gstRate: { type: Number, default: 5 }, 
      commissionAmount: Number,
      gstAmount: Number,
      netPayoutToSeller: Number
    }
  ],

  paymentMethod: { type: String, required: true, default: "Cash on Delivery" },
  totalAmount: { type: Number, required: true },
  promoDiscount: { type: Number, default: 0 },
  finalAmount: { type: Number, required: true },

  orderStatus: { type: String, default: 'Pending' },
  orderedAt: { type: Date, default: Date.now }
}, { versionKey: false });

const Order = mongoose.model('Order', orderSchema);


app.post('/api/place-order', async (req, res) => {
  try {
    const {
      phone,
      promoDiscount,
      paymentMethod,
      products,
      totalAmount,
      addressId
    } = req.body;

    if (!phone || !products || products.length === 0 || !addressId) {
      return res.status(400).json({ success: false, message: "Missing order data or address" });
    }

    // ✅ Check stock availability
    for (const p of products) {
      const dbProduct = await Product.findById(p.productId);
      if (!dbProduct || dbProduct.stock < p.quantity) {
        return res.status(400).json({
          success: false,
          message: `Insufficient stock for product: ${p.name}`
        });
      }
    }

    // ✅ Fetch address
    const address = await addressModel.findById(addressId);
    if (!address) {
      return res.status(404).json({ success: false, message: "Address not found" });
    }

    const finalAmount = Math.max(totalAmount - promoDiscount, 0);
    const orderId = `ORD-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${uuidv4().slice(0, 8).toUpperCase()}`;

    // ✅ Calculate product-level commissions and payouts
    const orderProducts = await Promise.all(products.map(async (p) => {
      const dbProduct = await Product.findById(p.productId).select('seller commissionRate gstRate sizes');

      const commissionRate = dbProduct?.commissionRate || 10;
      const gstRate = dbProduct?.gstRate || 5;

      const actualPrice = p.discountPrice || p.price;
      const totalPrice = actualPrice * p.quantity;

      const commissionAmount = (totalPrice * commissionRate) / 100;
      const gstAmount = (commissionAmount * gstRate) / 100;
      const netSellerPayout = totalPrice - commissionAmount - gstAmount;

      const hasSizeOptions = Array.isArray(dbProduct?.sizes) && dbProduct.sizes.length > 0;
      const size = hasSizeOptions ? p.selectedSize : "Free Size";

      if (hasSizeOptions && !p.selectedSize) {
        throw new Error(`Size must be selected for product: ${p.name}`);
      }

      return {
        productId: p.productId,
        name: p.name,
        image: p.image,
        quantity: p.quantity,
        price: actualPrice,
        totalcost: totalPrice,
        size,
        color: p.selectedColor || null,
        sellerId: dbProduct?.seller || null,
        commissionRate,
        gstRate,
        commissionAmount: parseFloat(commissionAmount.toFixed(2)),
        gstAmount: parseFloat(gstAmount.toFixed(2)),
        netPayoutToSeller: parseFloat(netSellerPayout.toFixed(2))
      };
    }));

    // ✅ Create order
    const newOrder = new Order({
      orderId,
      userPhone: phone,
      shippingAddress: address.toObject(),
      products: orderProducts,
      paymentMethod,
      totalAmount,
      promoDiscount,
      finalAmount
    });

    await newOrder.save();

    // ✅ Insert commission entries
    const commissionEntries = orderProducts
      .filter(item => item.sellerId) // prevent inserting null seller
      .map((item) => ({
        sellerId: item.sellerId,
        orderId: newOrder._id,
        productId: item.productId,
        productName: item.name,
        productPrice: item.totalcost,
        commissionRate: item.commissionRate,
        commissionAmount: item.commissionAmount,
        date: new Date()
      }));

    if (commissionEntries.length > 0) {
      await Commission.insertMany(commissionEntries);
      console.log("✅ Commission entries saved:", commissionEntries);
    } else {
      console.warn("⚠️ No valid commission entries to insert.");
    }

    // ✅ Update stock
    for (const p of products) {
      await Product.findByIdAndUpdate(
        p.productId,
        { $inc: { stock: -p.quantity } },
        { new: true }
      );
    }

    return res.json({
      success: true,
      message: "Order placed successfully",
      orderId,
      finalAmount,
      promoDiscount,
      totalAmount
    });

  } catch (err) {
    console.error("❌ Order error:", err);
    return res.status(500).json({ success: false, message: err.message || "Server error" });
  }
});




app.get('/api/seller/orders', authMiddleware, async (req, res) => {
  try {
    const sellerId = req.seller._id; // Comes from authMiddleware

    const orders = await Order.find({
      "products.sellerId": sellerId,
    }).sort({ orderedAt: -1 }); // latest orders first

    // Optional: filter only matching products per seller
    const filteredOrders = orders.map(order => ({
      ...order.toObject(),
      products: order.products.filter(p => p.sellerId?.toString() === sellerId.toString())
    }));

    return res.json({ success: true, orders: filteredOrders });
  } catch (err) {
    console.error("Error fetching seller orders:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});
app.get('/api/seller/total-sales', authMiddleware, async (req, res) => {
  try {
    const sellerId = req.seller._id;
    const { from, to, productId } = req.query;

    const orderQuery = {
      "products.sellerId": sellerId
    };

    // Apply date range filter if provided
    if (from || to) {
      orderQuery.orderedAt = {};
      if (from) orderQuery.orderedAt.$gte = new Date(from);
      if (to) orderQuery.orderedAt.$lte = new Date(to);
    }

    const orders = await Order.find(orderQuery).sort({ orderedAt: -1 });

    let totalSales = 0;
    let totalQuantity = 0;
    let totalDelivered = 0; // ✅ new variable

    const salesDetails = [];

    orders.forEach(order => {
      const totalOrderValue = order.products.reduce(
        (sum, p) => sum + (p.price * p.quantity),
        0
      );

      const finalAmount = order.finalAmount || totalOrderValue;
      const promoDiscountTotal = totalOrderValue - finalAmount;

      order.products.forEach(product => {
        const isForSeller = product.sellerId?.toString() === sellerId.toString();
        const isMatchingProduct = !productId || productId === product.productId?.toString();

        if (isForSeller && isMatchingProduct) {
          const productTotal = product.price * product.quantity;
          const proportion = totalOrderValue > 0 ? productTotal / totalOrderValue : 0;

          const adjustedSubtotal = finalAmount * proportion;
          const promoDiscountShare = productTotal - adjustedSubtotal;

          totalSales += adjustedSubtotal;
          totalQuantity += product.quantity;

          // ✅ Count delivered quantity
          if (order.orderStatus === 'Delivered') {
            totalDelivered += product.quantity;
          }

          salesDetails.push({
            orderId: order.orderId,
            productId: product.productId,
            productName: product.name,
            quantity: product.quantity,
            price: product.price,
            subtotal: adjustedSubtotal,
            promoDiscountShare: promoDiscountShare,
              gstAmount: product.gstAmount || 0,
  commissionAmount: product.commissionAmount || 0,
  netPayoutToSeller: product.netPayoutToSeller || 0,
            orderedAt: order.orderedAt,
            orderStatus: order.orderStatus // Optional for frontend display
          });
        }
      });
    });

    return res.json({
      success: true,
      totalSales,
      totalQuantity,
      totalDelivered, // ✅ Include in response
      salesCount: salesDetails.length,
      salesDetails
    });

  } catch (err) {
    console.error("Error fetching total sales:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});




app.put('/api/seller/order-status', authMiddleware, async (req, res) => {
  try {
    const { orderId, newStatus } = req.body;

    const order = await Order.findOne({ orderId });

    if (!order) return res.status(404).json({ success: false, message: 'Order not found' });

    // Only update products of this seller (optional safety step)
    const sellerId = req.seller._id.toString();
    order.products = order.products.map(p => {
      if (p.sellerId?.toString() === sellerId) {
        return { ...p };
      }
      return p;
    });

    order.orderStatus = newStatus;
    await order.save();

    return res.json({ success: true, message: 'Order status updated' });
  } catch (err) {
    console.error('Order update error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});
app.get('/api/user/orders', async (req, res) => {
  try {
    const encryptedPhone = req.query.phone;

    if (!encryptedPhone) {
      return res.status(400).json({ success: false, message: 'Missing phone param' });
    }

    let phone = null;

    try {
      const parsed = JSON.parse(decodeURIComponent(encryptedPhone));

      // ✅ Make sure this calls decryptaes and assigns result to phone
      phone = decryptaes(parsed.payload, parsed.iv);

      // ✅ Log the ACTUAL decrypted phone string
      console.log('✅ Decrypted phone:', phone);
    } catch (err) {
      console.log('⚠️ Error during decryption:', err.message);
    }

    if (!phone) {
      return res.status(400).json({ success: false, message: 'Invalid phone' });
    }

    const orders = await Order.find({ userPhone: phone }).sort({ orderedAt: -1 }).lean();

    res.json({ success: true, orders });
  } catch (err) {
    console.error('🔴 Error fetching orders:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});





app.post('/api/user/rate-product', userAuthMiddleware, async (req, res) => {
 const { productId, rating, review } = req.body;
  const userPhone = req.user.phone;

  // Basic input validation
 if (!productId || !rating || isNaN(rating) || rating < 1 || rating > 5) {
    return res.status(400).json({ error: 'Valid productId and rating (1-5) required' });
  }

  try {
    const product = await Product.findById(productId);
    if (!product) return res.status(404).json({ error: 'Product not found' });

    // Defensive check: ratings array must exist
   if (!Array.isArray(product.ratings)) {
  product.ratings = [];
} else {
  // Filter out any non-object junk like numbers or nulls
  product.ratings = product.ratings.filter(r => typeof r === 'object' && r !== null && !Array.isArray(r));
}
const existingRating = product.ratings.find(r => r.userPhone === userPhone);

    // Build a clean, validated rating object
    const newRating = {
      userPhone: String(userPhone),
      stars: Number(rating),
      review: String(review || ''),
      ratedAt: new Date()
    };

    if (existingRating) {
      // Update existing rating
      existingRating.stars = newRating.stars;
      existingRating.review = newRating.review;
      existingRating.ratedAt = newRating.ratedAt;
    } else {
      // ✅ Push only a valid rating object
      product.ratings.push(newRating);
    }

    // Recalculate average rating
    const totalStars = product.ratings.reduce((sum, r) => sum + Number(r.stars || 0), 0);
    const avgRating = product.ratings.length > 0 ? totalStars / product.ratings.length : 0;

    product.averageRating = parseFloat(avgRating.toFixed(2));

    // Optional: log before saving for debugging
    console.log("Final product.ratings:", product.ratings);

    await product.save();
    res.json({ success: true, message: 'Rating submitted successfully' });

  } catch (err) {
    console.error('Rating error:', err);
    res.status(500).json({ error: 'Failed to rate product' });
  }
});
app.get('/api/sellerproduct-ratings', authMiddleware, async (req, res) => {
  try {
    const sellerId = req.seller._id;

    // Get all products of this seller
    const products = await Product.find({ seller: sellerId }).lean();

    const ratings = [];

    for (const product of products) {
      if (Array.isArray(product.ratings)) {
        for (const rating of product.ratings) {
          // Find order matching userPhone and productId
          const order = await Order.findOne({
            userPhone: rating.userPhone,
            'products.productId': product._id
          }).lean();

          const userName = order?.shippingAddress?.name || rating.userPhone;

          ratings.push({
            productId: product._id,
            productName: product.title,
            productImage: product.thumbnail || product.images?.[0],
            stars: rating.stars,
            review: rating.review,
            userName, // ✅ Name from Order
            ratedAt: rating.ratedAt,
          });
        }
      }
    }

    // Optional: Sort by latest first
    ratings.sort((a, b) => new Date(b.ratedAt) - new Date(a.ratedAt));

    return res.json({ success: true, ratings });
  } catch (error) {
    console.error('Seller Ratings Fetch Error:', error);
    res.status(500).json({ success: false, error: 'Server Error' });
  }
});

app.get('/api/admin/orders', async (req, res) => {
  try {
    const orders = await Order.find()
      .sort({ orderedAt: -1 })
      .populate('products.productId', 'title') // optional: if you want product names from DB
      .populate('products.sellerId', 'companyName'); // optional: seller info

    res.json(orders);
  } catch (err) {
    console.error('Admin order fetch error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});
const adminSchema = new mongoose.Schema({
  name: String,
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
  },
  password: {
    type: String,
    required: true,
    minlength: 6,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const Admin = mongoose.model('Admin', adminSchema);
app.post('/api/adminregister', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existingAdmin = await Admin.findOne({ email });
    if (existingAdmin) return res.status(400).json({ error: 'Admin already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newAdmin = new Admin({ name, email, password: hashedPassword });

    await newAdmin.save();
    res.status(201).json({ message: 'Admin registered successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});
app.post('/api/adminlogin', async (req, res) => {
  let { email, password } = req.body;

  try {
    // ✅ Decode base64-obfuscated credentials
    email = decodeURIComponent(escape(Buffer.from(email, 'base64').toString()));
    password = decodeURIComponent(escape(Buffer.from(password, 'base64').toString()));
  } catch (e) {
    return res.status(400).json({ error: 'Invalid payload format' });
  }

  const admin = await Admin.findOne({ email });
  if (!admin) {
    return res.status(404).json({ error: 'Admin not found' });
  }

  const isMatch = await bcrypt.compare(password, admin.password);
  if (!isMatch) {
    return res.status(401).json({ error: 'Incorrect password' });
  }

  const token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

  // ✅ Encrypt full response
  const { payload, iv } = encryptaes(
    JSON.stringify({ admin, token, message: 'Login successful' })
  );

  return res.status(200).json({ payload, iv });
});
app.patch('/api/admin/approve-seller/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { isApprovedSeller } = req.body;

    const updatedSeller = await Seller.findByIdAndUpdate(
      id,
      { isApprovedSeller },
      { new: true }
    );

    if (!updatedSeller) {
      return res.status(404).json({ error: 'Seller not found.' });
    }

    res.json({ message: isApprovedSeller ? 'Seller approved' : 'Access revoked' });
  } catch (error) {
    console.error('Approval error:', error);
    res.status(500).json({ error: 'Server error.' });
  }
});
app.get('/api/admin/sellers', async (req, res) => {
  try {
    const sellers = await Seller.find({}, '-password')  // exclude password field
      .sort({ createdAt: -1 }); // newest first
    res.status(200).json(sellers);
  } catch (err) {
    console.error('Error fetching sellers:', err);
    res.status(500).json({ error: 'Failed to fetch sellers' });
  }
});
app.delete('/api/admin/products/:id', async (req, res) => {
  try {
    const productId = req.params.id;
    const product = await Product.findById(productId);
    if (!product) return res.status(404).json({ error: 'Product not found' });

    // Delete product images if needed (optional, like you do for sellers)

    await Product.findByIdAndDelete(productId);
    res.json({ message: 'Product deleted successfully' });
  } catch (err) {
    console.error('Admin delete error:', err);
    res.status(500).json({ error: 'Failed to delete product' });
  }
});
// PATCH /api/admin/product/commission/:id
app.patch('/api/admin/product/commission/:id', async (req, res) => {
  try {
    const { commissionRate } = req.body;
    if (typeof commissionRate !== 'number') {
      return res.status(400).json({ error: 'Invalid commission rate' });
    }

    const product = await Product.findByIdAndUpdate(
      req.params.id,
      { commissionRate },
      { new: true }
    );

    res.json({ message: 'Commission updated successfully', product });
  } catch (err) {
    console.error('Commission update error:', err);
    res.status(500).json({ error: 'Failed to update commission' });
  }
});
// Route: /api/admin/category-full-summary
app.get('/api/admin/category-product-summary', async (req, res) => {
  try {
    const summary = await Category.aggregate([
      {
        $lookup: {
          from: 'subcategories',
          localField: '_id',
          foreignField: 'category',
          as: 'subcategories'
        }
      },
      { $unwind: { path: '$subcategories', preserveNullAndEmptyArrays: true } },
      {
        $unwind: {
          path: '$subcategories.types',
          preserveNullAndEmptyArrays: true
        }
      },
      {
        $lookup: {
          from: 'products',
          let: {
            categoryId: '$_id',
            subcategoryId: '$subcategories._id',
            typeName: '$subcategories.types'
          },
          pipeline: [
            {
              $match: {
                $expr: {
                  $and: [
                    { $eq: ['$category', '$$categoryId'] },
                    { $eq: ['$subcategory', '$$subcategoryId'] },
                    { $eq: ['$type', '$$typeName'] }
                  ]
                }
              }
            },
            {
              $lookup: {
                from: 'Seller',
                localField: 'seller',
                foreignField: '_id',
                as: 'sellerDetails'
              }
            },
            {
              $unwind: {
                path: '$sellerDetails',
                preserveNullAndEmptyArrays: true
              }
            },
            {
              $project: {
                _id: 1,
                sellerName: {
                  $ifNull: ['$sellerDetails.companyName', 'Unknown Seller']
                }
              }
            }
          ],
          as: 'matchedProducts'
        }
      },
      {
        $addFields: {
          uniqueSellers: {
            $setUnion: ['$matchedProducts.sellerName', []]
          }
        }
      },
      {
        $project: {
          category: '$name',
          subcategory: '$subcategories.name',
          type: '$subcategories.types',
          productCount: { $size: '$matchedProducts' },
          sellers: '$uniqueSellers'
        }
      },
      {
        $sort: {
          category: 1,
          subcategory: 1,
          type: 1
        }
      }
    ]);

    res.json(summary);
  } catch (err) {
    console.error('Error in category summary:', err);
    res.status(500).json({ error: 'Failed to fetch category product summary' });
  }
});
app.get('/api/adminusers', async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 });
    res.status(200).json(users);
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});
app.patch('/api/admin/user/:id/block', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    user.isBlocked = !user.isBlocked;
    await user.save();
    res.status(200).json({ message: `User ${user.isBlocked ? 'blocked' : 'unblocked'}` });
  } catch (err) {
    console.error('Error blocking/unblocking user:', err);
    res.status(500).json({ error: 'Failed to update user' });
  }
});
app.patch('/api/admin/seller/:id/status', async (req, res) => {
  try {
    const seller = await Seller.findById(req.params.id);
    if (!seller) return res.status(404).json({ message: 'Seller not found' });

    if (req.body.hasOwnProperty('isBlocked')) {
      seller.isBlocked = req.body.isBlocked;
    }
    if (req.body.hasOwnProperty('isApprovedSeller')) {
      seller.isApprovedSeller = req.body.isApprovedSeller;
    }

    await seller.save();
    res.status(200).json({ message: 'Seller status updated' });
  } catch (err) {
    console.error('Error updating seller:', err);
    res.status(500).json({ error: 'Failed to update seller' });
  }
});
app.get('/api/commission-earned', async (req, res) => {
  try {
    const orders = await Order.find({ orderStatus: 'Delivered' })
      .populate('products.productId') // to get product details
      .populate('products.sellerId'); // to get seller details

    let totalCommission = 0;
    let totalGst = 0;
    let totalNetPayout = 0;
    let totalFinal = 0;

    const soldProducts = [];

    for (const order of orders) {
      totalFinal += order.finalAmount;

      for (const prod of order.products) {
        totalCommission += prod.commissionAmount || 0;
        totalGst += prod.gstAmount || 0;
        totalNetPayout += prod.netPayoutToSeller || 0;

        // Push product details for frontend table
     soldProducts.push({
  productName: prod.name || prod.productId?.name || 'N/A',
  price: prod.price || 0,
  quantity: prod.quantity || 1,
  sellerCompany: prod.sellerId?.companyName || 'Unknown Seller',
  orderDate: order.orderedAt || order.createdAt || new Date(),
  commission: prod.commissionAmount || 0,
  gst: prod.gstAmount || 0,
  discount: order.promoDiscount || 0,
  orderAmount: prod.totalProductAmount || (prod.price * prod.quantity),
  netPayout: prod.netPayoutToSeller || 0
});
      }
    }

    res.json({
      success: true,
      data: {
        totalCommission: parseFloat(totalCommission.toFixed(2)),
        totalGst: parseFloat(totalGst.toFixed(2)),
        totalFinal: parseFloat(totalFinal.toFixed(2)),
        totalNetPayout: parseFloat(totalNetPayout.toFixed(2)),
        totalOrders: orders.length,
        soldProducts
      }
    });
  } catch (err) {
    console.error('Commission API error:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});
app.get('/api/admin/total-sales', async (req, res) => {
  try {
    const orders = await Order.find({ orderStatus: 'Delivered' })
      .populate('products.productId')
      .populate('products.sellerId');

    const salesDetails = [];

    orders.forEach(order => {
      const totalOrderValue = order.products.reduce(
        (sum, p) => sum + (p.price * p.quantity),
        0
      );

      const finalAmount = order.finalAmount || totalOrderValue;

      order.products.forEach(p => {
        const productTotal = p.price * p.quantity;
        const proportion = totalOrderValue > 0 ? productTotal / totalOrderValue : 0;
        const adjustedSubtotal = finalAmount * proportion;
        const promoDiscountShare = productTotal - adjustedSubtotal;

        salesDetails.push({
          productName: p.name || p.productId?.name || 'Unknown Product',
          quantity: p.quantity,
          price: p.price,
          subtotal: adjustedSubtotal,
          promoDiscountShare: promoDiscountShare,
          gstAmount: p.gstAmount || 0,
          commissionAmount: p.commissionAmount || 0,
          netPayoutToSeller: p.netPayoutToSeller || 0,
          orderedAt: order.orderedAt,
          sellerCompany: p.sellerId?.companyName || 'Unknown Seller',
        });
      });
    });

    res.json({ success: true, salesDetails });
  } catch (err) {
    console.error('Admin total sales error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch sales data' });
  }
});

app.get('/api/admin/commission-settings', async (req, res) => {
  try {
    const categories = await Category.find({}, 'name commissionPercentage gstPercentage');
    res.json({ success: true, categories });
  } catch (error) {
    console.error('Error fetching commission settings:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});
app.put('/api/admin/commission-settings/:categoryId', async (req, res) => {
  const { commissionPercentage, gstPercentage } = req.body;
  try {
    const updated = await Category.findByIdAndUpdate(
      req.params.categoryId,
      { commissionPercentage, gstPercentage },
      { new: true }
    );
    res.json({ success: true, category: updated });
  } catch (error) {
    console.error('Error updating settings:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});
// routes/admin.js or wherever you're handling admin routes

app.get('/api/admin/featured-products', async (req, res) => {
  try {
    const featuredProducts = await Product.find({ isFeatured: true })
      .select('title thumbnail price discountPrice') // select necessary fields
      .lean();

    res.status(200).json({ success: true, products: featuredProducts });
  } catch (error) {
    console.error('Error fetching featured products:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});
app.get('/api/admin/all-ratings', async (req, res) => {
  try {
    const products = await Product.find().lean();

    // Preload all sellers and store in a map
    const allSellers = await Seller.find().lean();
    const sellerMap = {};
    allSellers.forEach(seller => {
      sellerMap[seller._id.toString()] =
        seller.companyName ||
        seller.bankDetails?.email ||
        seller.pickupAddress?.fullName ||
        'Unknown Seller';
    });

    // Preload all orders and build userPhone -> name map
    const allOrders = await Order.find().lean();
    const userMap = {};
    allOrders.forEach(order => {
      if (order.userPhone && order.shippingAddress?.name) {
        userMap[order.userPhone] = order.shippingAddress.name;
      }
    });

    const ratings = [];

    for (const product of products) {
      if (Array.isArray(product.ratings)) {
        for (const rating of product.ratings) {
          ratings.push({
            productName: product.title,
            productImage: product.thumbnail || product.images?.[0] || '',
            sellerName: sellerMap[product.seller?.toString()] || 'Unknown Seller',
            userName: userMap[rating.userPhone] || rating.userPhone,
            stars: rating.stars,
            review: rating.review,
            ratedAt: rating.ratedAt
          });
        }
      }
    }

    // Sort by date (most recent first)
    ratings.sort((a, b) => new Date(b.ratedAt) - new Date(a.ratedAt));

    res.json({ success: true, ratings });
  } catch (err) {
    console.error('Admin Ratings Fetch Error:', err);
    res.status(500).json({ success: false, error: 'Server Error' });
  }
});
const CommissionSchema = new mongoose.Schema({
  sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Seller', required: true },
  orderId: { type: mongoose.Schema.Types.ObjectId, ref: 'Order', required: true },
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  productName: String,
  productPrice: Number,
  commissionRate: Number, 
  commissionAmount: Number,
  date: { type: Date, default: Date.now },
});
const Commission=mongoose.model('Commission',CommissionSchema,'Commission')
app.get('/api/commission/seller', authMiddleware, async (req, res) => {
  try {
    const sellerId = req.seller._id; // ✅ corrected
    const commissions = await Commission.find({ sellerId }).sort({ date: -1 });
    res.json({ success: true, commissions });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});
const jobSchema = new mongoose.Schema({
  title: { type: String, required: true },
  department: String,
  location: String,
  type: { type: String, enum: ['Full-time', 'Part-time', 'Internship', 'Contract'], default: 'Full-time' },
  description: { type: String, required: true },
  requirements: [String],
  postedAt: { type: Date, default: Date.now }
});
const Jobs=mongoose.model("Jobs",jobSchema,"Jobs")
app.post('/api/post-job', async (req, res) => {
  try {
    const { title, department, location, type, description, requirements } = req.body;

    const newJob = new Jobs({
      title,
      department,
      location,
      type,
      description,
      requirements
    });

    await newJob.save();

    res.status(201).json({ success: true, message: 'Job posted successfully', job: newJob });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error posting job', error: error.message });
  }
});
app.get('/api/jobs', async (req, res) => {
  try {
    const jobs = await Jobs.find().sort({ postedAt: -1 });
    res.json({ jobs });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch jobs' });
  }
});

// DELETE job by ID
app.delete('/api/delete-job/:id', async (req, res) => {
  try {
    await Jobs.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ message: 'Failed to delete job' });
  }
});
const applicationSchema = new mongoose.Schema({
  job: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Jobs',
    required: true,
  },
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100,
  },
  email: {
    type: String,
    required: true,
    trim: true,
    lowercase: true,
    match: [/.+\@.+\..+/, 'Please fill a valid email address'],
  },
  contact: {
    type: String,
    required: true,
    trim: true,
    minlength: 7,
    maxlength: 20,
  },
  resumeUrl: {
    type: String,
    required: true, // Resume must be uploaded
  },
}, {
  timestamps: true
});
const jobApplication=mongoose.model("jobApplication",applicationSchema,"jobApplication"); 
app.post('/api/applyjob', uploadResume.single('resume'), async (req, res) => {
  try {
    const { name, email, contact, job } = req.body;

    if (!req.file) {
      return res.status(400).json({ success: false, message: 'Resume is required.' });
    }

    const application = new jobApplication({
      job,
      name,
      email,
      contact,
      resumeUrl: `/uploads/resumes/${req.file.filename}`,
    });

    await application.save();
    res.status(201).json({ success: true, message: 'Application submitted successfully.' });
  } catch (err) {
    console.error('Error applying:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});
app.get('/api/applications/:jobId', async (req, res) => {
  try {
    const jobId = req.params.jobId;
    const applications = await jobApplication.find({ job: jobId }).sort({ createdAt: -1 });
    res.json({ success: true, applications });
  } catch (err) {
    console.error('Error fetching applications:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});
app.get('/api/applications', async (req, res) => {
  try {
    const applications = await jobApplication.find().populate('job', 'title').sort({ createdAt: -1 });
    res.json({ success: true, applications });
  } catch (err) {
    console.error('Error fetching all applications:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});
app.get('/api/jobs/:id', async (req, res) => {
  try {
    const job = await Jobs.findById(req.params.id);
    if (!job) {
      return res.status(404).json({ success: false, message: 'Job not found' });
    }
    res.status(200).json(job);
  } catch (err) {
    console.error('Error fetching job:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});



















// Start server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
