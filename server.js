const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db');
const dotenv = require('dotenv');
const cors = require('cors');

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
app.use(cors());
app.use(express.json());



// Sign up route
const crypto = require('crypto'); // For generating unique referral codes


app.post('/signup', (req, res) => {
    const { name, phone_number, password, referralCode } = req.body; // Include referralCode in the request body

    // Validate input fields
    if (!name || !phone_number || !password) {
        return res.status(400).json({ message: 'Please provide name, phone_number, and password.' });
    }

    // Check if the user already exists
    db.query('SELECT * FROM users WHERE phone_number = ?', [phone_number], (err, results) => {
        if (err) {
            return res.status(500).json({ message: 'Database error during user check.' });
        }

        if (results.length > 0) {
            return res.status(400).json({ message: 'User already exists.' });
        }

        // Hash the password
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                return res.status(500).json({ message: 'Error hashing password.' });
            }

            // Generate a unique referral code for the new user
            const userReferralCode = crypto.randomBytes(6).toString('hex'); // 12-character unique code

            // Handle referral logic if referralCode is provided
            const processReferral = (callback) => {
                if (!referralCode) {
                    return callback(null); // No referral code provided, proceed without updating
                }

                // Check if the referral code exists in the database
                db.query('SELECT * FROM users WHERE referral_code = ?', [referralCode], (err, referrerResults) => {
                    if (err) {
                        return res.status(500).json({ message: 'Database error while verifying referral code.' });
                    }

                    if (referrerResults.length === 0) {
                        return res.status(400).json({ message: 'Invalid referral code.' });
                    }

                    // Increment `pending_referral` for the referrer
                    const referrerId = referrerResults[0].id;
                    db.query(
                        'UPDATE users SET pending_referral = IFNULL(pending_referral, 0) + 1 WHERE id = ?',
                        [referrerId],
                        (err) => {
                            if (err) {
                                return res.status(500).json({ message: 'Database error while updating referral count.' });
                            }

                            // Referral processed successfully; pass the referrerId to the callback
                            return callback(referrerId);
                        }
                    );
                });
            };

            processReferral((referrerId) => {
                // Insert the new user into the database
                db.query(
                    'INSERT INTO users (name, phone_number, password, status, referral_code, referred_by) VALUES (?, ?, ?, ?, ?, ?)',
                    [name, phone_number, hashedPassword, null, userReferralCode, referrerId || null],
                    (err, result) => {
                        if (err) {
                            return res.status(500).json({ message: 'Error saving user to the database.' });
                        }

                        // Generate JWT token
                        const payload = { userId: result.insertId };

                        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '6h' });

                        // Return success response with user details and referral info
                        return res.status(201).json({
                            message: 'User signed up successfully!',
                            token: token,
                            user: {
                                id: result.insertId,
                                name: name,
                                phone_number: phone_number,
                                referral_code: userReferralCode,
                                referred_by: referrerId || null, // Referrer's ID, if any
                            },
                        });
                    }
                );
            });
        });
    });
});






// JWT Middleware for Protected Routes
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(403).json({ message: 'No token provided.' });
    }

    // Remove 'Bearer ' prefix
    const tokenWithoutBearer = token.split(' ')[1];


        jwt.verify(tokenWithoutBearer, process.env.JWT_SECRET, (err, decoded) => {
            if (err) {
                console.error('JWT Verification Error:', err.name, err.message);
                return res.status(401).json({ message: 'Unauthorized' });
            }

            console.log('Decoded Token (after verifying):', decoded);
            req.userId = decoded.userId; // Attach userId to request
            next();
        });

};



app.patch('/user/:id/update-plan',  (req, res) => {
    const userId = req.params.id;
    const { plan_name } = req.body; // The new plan name selected by the user

    // Validate that the plan_name is provided
    if (!plan_name) {
        return res.status(400).json({ message: 'Plan name is required' });
    }

    // Query to fetch the plan details based on the provided plan_name
    db.query('SELECT id FROM subscriptions WHERE plan_name = ?', [plan_name], (err, results) => {
        if (err) {
            console.error('Error fetching plan details:', err);
            return res.status(500).json({ message: 'Database query error' });
        }

        // If no matching plan is found, return an error
        if (results.length === 0) {
            return res.status(404).json({ message: 'Plan not found' });
        }

        const subscriptionId = results[0].id; // Get the plan's ID

        // Now, update the user with the new subscription ID
        db.query('UPDATE users SET subscription_id = ? WHERE id = ?', [subscriptionId, userId], (err, result) => {
            if (err) {
                console.error('Error updating user plan information:', err);
                return res.status(500).json({ message: 'Error updating user plan information' });
            }

            // Return a success message
            return res.status(200).json({
                message: 'User plan updated successfully',
                user: {
                    id: userId,
                    subscription_id: subscriptionId,
                }
            });
        });
    });
});





// Login route
app.post('/login', (req, res) => {
    const { phone_number, password } = req.body;

    if (!phone_number || !password) {
        return res.status(400).json({ message: 'Please provide both email and password.' });
    }

    // Find the user by email and get subscription data
    db.query(`
        SELECT u.id, u.name, u.role, u.status, u.phone_number, u.referral_code, u.password, s.plan_name, s.price, s.description
        FROM users u
        LEFT JOIN subscriptions s ON u.subscription_id = s.id
        WHERE u.phone_number = ?`, [phone_number], async (err, results) => {
        if (err) {
            return res.status(500).json({ message: 'Database query error' });
        }

        if (results.length === 0) {
            return res.status(400).json({ message: 'User not found.' });
        }

        const user = results[0];

        // Compare the entered password with the hashed password in the database
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }

        // Generate JWT Token
        const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // Construct user object with subscription data

        const userWithSubscription = {
            id: user.id,
            name: user.name,
            phone_number: user.phone_number,
            referral_code:user.referral_code,
            role:user.role,
            status:user.status,
            subscription: {
                plan_name: user.plan_name,
                price: user.price,
                description: user.description
            }
        };

        return res.status(200).json({
            message: 'Login successful!',
            token,
            user: userWithSubscription
        });
    });
});






// Get all users route
app.get('/users', (req, res) => {
    // Query the database to get all users along with their subscription details
    db.query(`
        SELECT u.id, u.name, u.role, u.pending_referral,u.active_referral, u.phone_number,   u.status, s.plan_name, s.price, s.description, s.daily_income
        FROM users u
        LEFT JOIN subscriptions s ON u.subscription_id = s.id`, (err, results) => {
        if (err) {
            return res.status(500).json({ message: 'Database query error' });
        }

        // Check if there are any users
        if (results.length === 0) {
            return res.status(404).json({ message: 'No users found' });
        }

        // Return the users list along with subscription info
        res.status(200).json({
            message: 'Users fetched successfully!',
            users: results
        });
    });
});


// get user details
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;

    db.query(`
        SELECT *
        FROM users u
        LEFT JOIN subscriptions s ON u.subscription_id = s.id
        WHERE u.id = ?`, [userId], (err, results) => {
        if (err) {
            return res.status(500).json({ message: 'Database query error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        const user = results[0];
        const userWithSubscription = {
            id: userId,
            name: user.name,
            phone_number: user.phone_number,
            referral_code:user.referral_code,
            role:user.role,
            status:user.status,
            subscription: {
                plan_name: user.plan_name,
                price: user.price,
                description: user.description,
                daily_income: user.daily_income
            }
        };

        return res.status(200).json({
            message: 'User profile fetched successfully',
            user: userWithSubscription, // Contains user details and associated plan details
        });
    });
});




// Update user status route
app.patch('/user/:id/status', (req, res) => {
    const userId = req.params.id; // Get user ID from route parameter
    const { status } = req.body; // Get status from request body

    // Ensure the status is valid (e.g., 'active' or 'inactive')
    if (status !== 'active' && status !== 'inactive' && status !== null) {
        return res.status(400).json({ message: 'Invalid status value. Allowed values: active, inactive, or null.' });
    }

    // Check if the user exists in the database
    db.query('SELECT * FROM users WHERE id = ?', [userId], (err, results) => {
        if (err) {
            console.error('Database error fetching user:', err); // Log the error
            return res.status(500).json({ message: 'Database query error.' });
        }

        if (results.length === 0) {
            console.error('User not found.'); // Log if user is not found
            return res.status(404).json({ message: 'User not found.' });
        }

        // Fetch the user's details, including their subscription plan
        db.query(`
            SELECT u.id, u.name, u.status, s.plan_name, s.price, s.description, u.referred_by
            FROM users u
            LEFT JOIN subscriptions s ON u.subscription_id = s.id
            WHERE u.id = ?`, [userId], (err, updatedUser) => {
            if (err) {
                console.error('Error fetching user and subscription details:', err);  // Log the error
                return res.status(500).json({ message: 'Error fetching user details.' });
            }

            const user = updatedUser[0];

            // Check if the user has no plan and prevent status change
            if (!user.plan_name) {
                console.error('Cannot change status. User has no subscription plan.');
                return res.status(400).json({ message: 'Cannot change status. User has no subscription plan.' });
            }

            // Update the user's status
            db.query('UPDATE users SET status = ? WHERE id = ?', [status, userId], (err, result) => {
                if (err) {
                    console.error('Error updating user status:', err);  // Log the error
                    return res.status(500).json({ message: 'Error updating user status.' });
                }

                // Handle balance update logic if the user is activated and has a price
                if (status === 'active' && user.price) {
                    const dailyIncome = user.price;

                    // Check if the user already has a balance record for today
                    db.query('SELECT * FROM balance WHERE user_id = ? AND DATE(created_at) = CURDATE()', [userId], (err, balanceRecord) => {
                        if (err) {
                            console.error('Error checking existing balance record:', err); // Log error
                            return res.status(500).json({ message: 'Error checking balance record.' });
                        }

                        if (balanceRecord.length > 0) {
                            // Update the existing balance record
                            db.query('UPDATE balance SET amount = ? WHERE user_id = ? AND DATE(created_at) = CURDATE()', [dailyIncome, userId], (err, updateResult) => {
                                if (err) {
                                    console.error('Error updating balance:', err); // Log error
                                    return res.status(500).json({ message: 'Error updating balance.' });
                                }

                                // Increment the referrer's active_referral count if a referrer exists
                                if (user.referred_by) {
                                    console.log('Referred By:', user.referred_by);
                                
                                    // Check if the referral already exists in the user_referrals table
                                    db.query('SELECT * FROM user_referrals WHERE user_id = ? AND referrer_id = ?', [userId, user.referred_by], (err, referralRecord) => {
                                        if (err) {
                                            console.error('Error checking referral record:', err);  // Log error
                                            return res.status(500).json({ message: 'Error checking referral record.' });
                                        }
                                
                                        if (referralRecord.length > 0) {
                                            // If the referral already exists, skip the update
                                            console.log('Referral already counted for this user.');
                                            return res.status(200).json({
                                                message: 'Referral already counted for this user.',
                                                user: user
                                            });
                                        }
                                
                                        // Update the referral count for the referrer if not duplicated
                                        db.query('UPDATE users SET active_referral = IFNULL(active_referral, 0) + 1 WHERE id = ?', [user.referred_by], (err, updateReferral) => {
                                            if (err) {
                                                console.error('Error updating active referral count:', err);  // Log error
                                                return res.status(500).json({ message: 'Error updating referral count.' });
                                            }
                                
                                            console.log('Referral count updated for user ID:', user.referred_by);
                                
                                            // Insert the referral record into the user_referrals table
                                            db.query('INSERT INTO user_referrals (user_id, referrer_id) VALUES (?, ?)', [userId, user.referred_by], (err, insertReferral) => {
                                                if (err) {
                                                    console.error('Error inserting referral record:', err);
                                                    return res.status(500).json({ message: 'Error tracking referral.' });
                                                }
                                
                                                // Calculate total balance for the user
                                                db.query('SELECT SUM(amount) AS total_balance FROM balance WHERE user_id = ?', [userId], (err, result) => {
                                                    if (err) {
                                                        console.error('Error calculating total balance:', err);  // Log error
                                                        return res.status(500).json({ message: 'Error calculating total balance.' });
                                                    }
                                
                                                    const totalBalance = result[0].total_balance;
                                                    return res.status(200).json({
                                                        message: 'User status updated successfully and balance updated!',
                                                        user: user, // Full user details with subscription
                                                        total_balance: totalBalance
                                                    });
                                                });
                                            });
                                        });
                                    });
                                }
                                
                                 else {
                                    // No referral, just update balance
                                    db.query('SELECT SUM(amount) AS total_balance FROM balance WHERE user_id = ?', [userId], (err, result) => {
                                        if (err) {
                                            console.error('Error calculating total balance:', err); // Log error
                                            return res.status(500).json({ message: 'Error calculating total balance.' });
                                        }

                                        const totalBalance = result[0].total_balance;
                                        return res.status(200).json({
                                            message: 'User status updated successfully and balance inserted!',
                                            user: user, // Full user details with subscription
                                            total_balance: totalBalance
                                        });
                                    });
                                }
                            });
                        } else {
                            // Insert a new balance record for the user
                            db.query('INSERT INTO balance (user_id, amount) VALUES (?, ?)', [userId, dailyIncome], (err, result) => {
                                if (err) {
                                    console.error('Error inserting into balance table:', err); // Log error
                                    return res.status(500).json({ message: 'Error updating balance.' });
                                }

                                // Increment the referrer's active_referral count if a referrer exists
                                if (user.referred_by) {
                                    // Check if the referral already exists in the user_referrals table
                                    db.query('SELECT * FROM user_referrals WHERE user_id = ? AND referrer_id = ?', [userId, user.referred_by], (err, referralRecord) => {
                                        if (err) {
                                            console.error('Error checking referral record:', err);  // Log error
                                            return res.status(500).json({ message: 'Error checking referral record.' });
                                        }
                                
                                        if (referralRecord.length > 0) {
                                            // If the referral already exists, skip the update
                                            return res.status(200).json({
                                                message: 'Referral already counted for this user.',
                                                user: user
                                            });
                                        }
                                
                                        // Update the referral count for the referrer if not duplicated
                                        db.query('UPDATE users SET active_referral = IFNULL(active_referral, 0) + 1 WHERE id = ?', [user.referred_by], (err, updateReferral) => {
                                            if (err) {
                                                console.error('Error updating active referral count:', err);  // Log error
                                                return res.status(500).json({ message: 'Error updating referral count.' });
                                            }
                                
                                            console.log('Referral count updated for user ID:', user.referred_by);
                                
                                            // Insert the referral record into the user_referrals table
                                            db.query('INSERT INTO user_referrals (user_id, referrer_id) VALUES (?, ?)', [userId, user.referred_by], (err, insertReferral) => {
                                                if (err) {
                                                    console.error('Error inserting referral record:', err);
                                                    return res.status(500).json({ message: 'Error tracking referral.' });
                                                }
                                

                                                    const referrerId = user.referred_by; // Referrer ID
                                                    const userId = user.id; // User ID (referred user)

                                                    // Fetch the daily income of the referred user
                                                    db.query(`
                                                        SELECT s.daily_income 
                                                        FROM users u
                                                        LEFT JOIN subscriptions s ON u.subscription_id = s.id
                                                        WHERE u.id = ?
                                                    `, [userId], (err, results) => {
                                                        
                                                        if (err) {
                                                            console.error('Error retrieving daily income:', err);
                                                            return res.status(500).json({ message: 'Error retrieving daily income.' });
                                                        }

                                                        if (results.length === 0 || results[0].daily_income === null) {
                                                            return res.status(404).json({ message: 'No daily income found for this user.' });
                                                        }

                                                        const dailyIncome = results[0].daily_income;
                                                        const amount = 2 * dailyIncome; // Calculating the amount for the referrer (2 times the daily income)

                                                        // Check if the referrer has already requested a payment today
                                                        db.query(
                                                            'SELECT * FROM pending_payments WHERE user_id = ? AND DATE(created_at) = ?',
                                                            [referrerId, new Date().toISOString().split('T')[0]], // Today's date
                                                            (err, results) => {
                                                                if (err) {
                                                                    console.error('Error checking previous transactions:', err); // Log error
                                                                    return res.status(500).json({ message: 'Error checking previous transactions.' });
                                                                }

                                                                // Insert into pending_payments table if no transaction for today
                                                                db.query('INSERT INTO pending_payments (user_id, amount, status) VALUES (?, ?, ?)', [referrerId, amount, 'pending'], (err, result) => {
                                                                    if (err) {
                                                                        return res.status(500).json({ message: 'Error creating transaction request.' });
                                                                    }

                                                                    return res.status(201).json({
                                                                        message: 'Referral and transaction request processed successfully.',
                                                                        transactionId: result.insertId, // Return the ID of the created transaction
                                                                        user: user // Full user details
                                                                    });
                                                                });
                                                            }
                                                        );
                                                    });

                                            });
                                        });
                                    });
                                }
                                 else {
                                    // No referral, just update balance
                                    db.query('SELECT SUM(amount) AS total_balance FROM balance WHERE user_id = ?', [userId], (err, result) => {
                                        if (err) {
                                            console.error('Error calculating total balance:', err); // Log error
                                            return res.status(500).json({ message: 'Error calculating total balance.' });
                                        }

                                        const totalBalance = result[0].total_balance;
                                        return res.status(200).json({
                                            message: 'User status updated successfully and balance inserted!',
                                            user: user, // Full user details with subscription
                                            total_balance: totalBalance
                                        });
                                    });
                                }
                            });
                        }
                    });
                } else {
                    return res.status(200).json({
                        message: 'User status updated successfully!',
                        user: user // User data without subscription change
                    });
                }
            });
        });
    });
});





// Add or modify a subscription
app.post('/subscription', (req, res) => {
    const { id, plan_name, price, description, daily_income } = req.body;

    // Check if the required fields are provided
    if (!plan_name || !price || !description || !daily_income) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    // If `id` is provided, update the existing subscription
    if (id) {
        db.query('SELECT * FROM subscriptions WHERE id = ?', [id], (err, results) => {
            if (err) {
                return res.status(500).json({ message: 'Database query error' });
            }

            if (results.length === 0) {
                return res.status(404).json({ message: 'Subscription not found' });
            }

            // Update subscription
            db.query('UPDATE subscriptions SET plan_name = ?, price = ?, description = ?, daily_income = ? WHERE id = ?',
                [plan_name, price, description, daily_income, id], (err, result) => {
                    if (err) {
                        return res.status(500).json({ message: 'Error updating subscription' });
                    }
                    return res.status(200).json({
                        message: 'Subscription updated successfully!',
                        subscription: { id, plan_name, price, description, daily_income }
                    });
                });
        });
    } else {
        // If `id` is not provided, add a new subscription
        db.query('INSERT INTO subscriptions (plan_name, price, description, daily_income) VALUES (?, ?, ?, ?)',
            [plan_name, price, description, daily_income], (err, result) => {
                if (err) {
                    return res.status(500).json({ message: 'Error adding subscription' });
                }
                return res.status(201).json({
                    message: 'Subscription added successfully!',
                    subscription: { id: result.insertId, plan_name, price, description, daily_income }
                });
            });
    }
});


// Get all subscription plans
app.get('/subscriptions', (req, res) => {
    // Query the database to get all subscriptions
    db.query('SELECT * FROM subscriptions', (err, results) => {
        if (err) {
            return res.status(500).json({ message: 'Database query error' });
        }

        // Check if there are any subscriptions
        if (results.length === 0) {
            return res.status(404).json({ message: 'No subscriptions found' });
        }

        // Return the list of subscriptions
        res.status(200).json({
            message: 'Subscriptions fetched successfully!',
            subscriptions: results
        });
    });
});

// Delete a subscription
app.delete('/subscription/:id', (req, res) => {
    const subscriptionId = req.params.id; // Get subscription ID from route parameter

    // Query the database to check if the subscription exists
    db.query('SELECT * FROM subscriptions WHERE id = ?', [subscriptionId], (err, results) => {
        if (err) {
            return res.status(500).json({ message: 'Database query error' });
        }

        // If subscription doesn't exist
        if (results.length === 0) {
            return res.status(404).json({ message: 'Subscription not found' });
        }

        // Delete the subscription from the database
        db.query('DELETE FROM subscriptions WHERE id = ?', [subscriptionId], (err, result) => {
            if (err) {
                return res.status(500).json({ message: 'Error deleting subscription' });
            }

            // Return a success message
            res.status(200).json({
                message: 'Subscription deleted successfully!',
                deletedSubscriptionId: subscriptionId
            });
        });
    });
});

// Get a single subscription by ID
app.get('/subscription/:id', (req, res) => {
    const subscriptionId = req.params.id;

    // Query the database to get the subscription with the provided ID
    db.query('SELECT * FROM subscriptions WHERE id = ?', [subscriptionId], (err, results) => {
        if (err) {
            return res.status(500).json({ message: 'Database query error' });
        }

        // Check if the subscription was found
        if (results.length === 0) {
            return res.status(404).json({ message: `Subscription with ID ${subscriptionId} not found` });
        }

        // Return the subscription
        res.status(200).json({
            message: 'Subscription fetched successfully!',
            subscription: results[0]
        });
    });
});











/////////////////////////transactions request

// POST: Create a new transaction request (pending) with the restriction of one per day
app.post('/transaction', (req, res) => {
    const { userId, amount } = req.body;
  
    // Validate input data
    if (!userId || !amount || amount <= 0) {
      return res.status(400).json({ message: 'Invalid request. Ensure userId and amount are provided.' });
    }
  
    // Get the current date (to compare with previous transaction requests)
    const currentDate = new Date().toISOString().split('T')[0]; // Format YYYY-MM-DD
  
    // Check if the user has already requested a payment today
    db.query(
      'SELECT * FROM pending_payments WHERE user_id = ? AND DATE(created_at) = ?',
      [userId, currentDate],
      (err, results) => {
        if (err) {
          return res.status(500).json({ message: 'Error checking previous transactions' });
        }
  
        if (results.length > 0) {
          // User already requested a payment today
          return res.status(400).json({ message: 'You can only request a payment once per day.' });
        }
  
        // Proceed to insert into pending_payments table if no transaction for today
        db.query('INSERT INTO pending_payments (user_id, amount, status) VALUES (?, ?, ?)', [userId, amount, 'pending'], (err, result) => {
          if (err) {
            return res.status(500).json({ message: 'Error creating transaction request' });
          }
  
          return res.status(201).json({
            message: 'Transaction request created successfully',
            transactionId: result.insertId // Return the ID of the created transaction
          });
        });
      }
    );
  });



// PATCH: Admin approves or rejects a transaction
app.patch('/transaction/approve/:id', (req, res) => {
    const transactionId = req.params.id;
    const { status } = req.body; // 'approved' or 'rejected'

    // Validate status
    if (status !== 'approved' && status !== 'rejected') {
        return res.status(400).json({ message: 'Invalid status value. Allowed values: approved, rejected.' });
    }

    // Check if the transaction exists in pending_payments
    db.query('SELECT * FROM pending_payments WHERE id = ?', [transactionId], (err, results) => {
        if (err) {
            console.error('Database query error:', err); // Log the error
            return res.status(500).json({ message: 'Error fetching pending payment' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: 'Transaction not found' });
        }

        const { user_id, amount } = results[0];

        // Check if the user has already approved a transaction today
        db.query(
            'SELECT * FROM transactions WHERE user_id = ? AND status = "completed" AND DATE(transaction_date) = CURDATE()',
            [user_id],
            (err, transactions) => {
                if (err) {
                    console.error('Error fetching transactions:', err); // Log the error
                    return res.status(500).json({ message: 'Error fetching transactions' });
                }

                if (transactions.length > 0) {
                    return res.status(400).json({ message: 'User has already approved a transaction today' });
                }

                // Begin a transaction to ensure atomicity
                db.beginTransaction((err) => {
                    if (err) {
                        console.error('Error starting transaction:', err);
                        return res.status(500).json({ message: 'Error starting transaction' });
                    }

                    // If approved, move to transactions table
                    if (status === 'approved') {
                        const currentDate = new Date().toISOString().slice(0, 19).replace('T', ' '); // Get current date

                        // Insert into transactions table
                        db.query(
                            'INSERT INTO transactions (user_id, amount, status, transaction_date) VALUES (?, ?, ?, ?)',
                            [user_id, amount, 'completed', currentDate],
                            (err, result) => {
                                if (err) {
                                    console.error('Error inserting into transactions table:', err);
                                    return db.rollback(() => {
                                        return res.status(500).json({ message: 'Error inserting transaction into transactions table' });
                                    });
                                }

                                // Update the pending_payment status to 'completed'
                                db.query(
                                    'UPDATE pending_payments SET status = ?, approved_at = ? WHERE id = ?',
                                    ['completed', currentDate, transactionId],
                                    (err, result) => {
                                        if (err) {
                                            console.error('Error updating pending payment status:', err);
                                            return db.rollback(() => {
                                                return res.status(500).json({ message: 'Error updating pending payment status' });
                                            });
                                        }

                                        // Update the balance table: deduct the amount
                                        db.query(
                                            'UPDATE balance SET amount = amount - ? WHERE user_id = ?',
                                            [amount, user_id],
                                            (err, result) => {
                                                if (err) {
                                                    console.error('Error updating balance:', err);
                                                    return db.rollback(() => {
                                                        return res.status(500).json({ message: 'Error updating balance' });
                                                    });
                                                }

                                                // Commit the transaction if all queries are successful
                                                db.commit((err) => {
                                                    if (err) {
                                                        console.error('Error committing transaction:', err);
                                                        return db.rollback(() => {
                                                            return res.status(500).json({ message: 'Error committing transaction' });
                                                        });
                                                    }

                                                    return res.status(200).json({ message: 'Transaction approved, completed, and balance updated successfully' });
                                                });
                                            }
                                        );
                                    }
                                );
                            }
                        );
                    } else {
                        // If rejected, update the status in pending_payments
                        db.query(
                            'UPDATE pending_payments SET status = ? WHERE id = ?',
                            ['rejected', transactionId],
                            (err, result) => {
                                if (err) {
                                    console.error('Error updating pending payment status to rejected:', err);
                                    return db.rollback(() => {
                                        return res.status(500).json({ message: 'Error updating pending payment status' });
                                    });
                                }

                                // Commit the transaction if rejected
                                db.commit((err) => {
                                    if (err) {
                                        console.error('Error committing transaction:', err);
                                        return db.rollback(() => {
                                            return res.status(500).json({ message: 'Error committing transaction' });
                                        });
                                    }

                                    return res.status(200).json({ message: 'Transaction rejected successfully' });
                                });
                            }
                        );
                    }
                });
            }
        );
    });
});

  
  
  

  

// GET: Fetch all pending payments
app.get('/pending-payments', (req, res) => {
    db.query('SELECT * FROM pending_payments WHERE status = "pending"', (err, results) => {
      if (err) {
        return res.status(500).json({ message: 'Database query error' });
      }
  
      if (results.length === 0) {
        return res.status(404).json({ message: 'No pending payments found' });
      }
  
      return res.status(200).json({
        message: 'Pending payments fetched successfully!',
        pendingPayments: results,
      });
    });
  });

  
  // GET: Fetch all completed payments
app.get('/completed-payments', (req, res) => {
    db.query('SELECT * FROM transactions WHERE status = "completed"', (err, results) => {
      if (err) {
        return res.status(500).json({ message: 'Database query error' });
      }
  
      if (results.length === 0) {
        return res.status(404).json({ message: 'No completed payments found' });
      }
  
      return res.status(200).json({
        message: 'Completed payments fetched successfully!',
        completedPayments: results,
      });
    });
  });

app.get('/all-balances', (req, res) => {
    const query = `
            SELECT 
            b.user_id, 
            b.amount AS balance, 
            IFNULL(SUM(t.amount), 0) AS daily_transaction_total
        FROM 
            balance b
        LEFT JOIN 
            transactions t 
        ON 
            b.user_id = t.user_id 
            AND t.status = 'completed' 
            AND DATE(t.transaction_date) = CURDATE()
        GROUP BY 
            b.user_id, b.amount

            `;

    db.query(query, (err, results) => {
        if (err) {
            console.error('Database query error:', err);
            return res.status(500).json({ message: 'Database query error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: 'No balance records found' });
        }

        return res.status(200).json({
            message: 'All balance records fetched successfully!',
            balances: results,
        });
    });
});


  
  
  






app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
