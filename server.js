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
app.post('/signup', (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ message: 'Please provide name, email, and password.' });
    }

    // Check if the user already exists
    db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }

        if (results.length > 0) {
            return res.status(400).json({ message: 'User already exists.' });
        }

        // Hash the password
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                return res.status(500).json({ message: 'Error hashing password.' });
            }

            // Insert the new user into the database with `status` as `NULL`
            db.query('INSERT INTO users (name, email, password, status) VALUES (?, ?, ?, ?)', [name, email, hashedPassword, null], (err, result) => {
                if (err) {
                    return res.status(500).json({ message: 'Error saving user to the database.' });
                }

                // Generate JWT token
                const payload = {
                    userId: result.insertId,  // User ID is taken from the inserted row's ID
                };

                // Sign the JWT token with the user ID and a secret key
                const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '6h' });

                // Return the token and user details
                return res.status(201).json({
                    message: 'User signed up successfully!',
                    token: token,  // Include the token in the response
                    user: {
                        id: result.insertId,
                        name: name,
                        email: email,
                    }
                });
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



app.patch('/user/:id/update-plan', verifyToken, (req, res) => {
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
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Please provide both email and password.' });
    }

    // Find the user by email and get subscription data
    db.query(`
        SELECT u.id, u.name, u.role, u.email, u.password, s.plan_name, s.price, s.description
        FROM users u
        LEFT JOIN subscriptions s ON u.subscription_id = s.id
        WHERE u.email = ?`, [email], async (err, results) => {
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
            email: user.email,
            role:user.role,
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
        SELECT u.id, u.name, u.role, u.email, u.status, s.plan_name, s.price, s.description, s.daily_income
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
app.get('/user/:id', verifyToken, (req, res) => {
    const userId = req.params.id;

    db.query(`
        SELECT u.id, u.name, u.email, u.status, s.plan_name, s.price, s.description, s.daily_income
        FROM users u
        LEFT JOIN subscriptions s ON u.subscription_id = s.id
        WHERE u.id = ?`, [userId], (err, results) => {
        if (err) {
            return res.status(500).json({ message: 'Database query error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        return res.status(200).json({
            message: 'User profile fetched successfully',
            user: results[0], // Contains user details and associated plan details
        });
    });
});




// Update user status route
app.patch('/user/:id/status', verifyToken, (req, res) => {
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

        // Update the user's status
        db.query('UPDATE users SET status = ? WHERE id = ?', [status, userId], (err, result) => {
            if (err) {
                console.error('Error updating user status:', err);  // Log the error
                return res.status(500).json({ message: 'Error updating user status.' });
            }

            // Fetch the updated user and subscription data
            db.query(`
                SELECT u.id, u.name, u.email, u.status, s.plan_name, s.price, s.description
                FROM users u
                LEFT JOIN subscriptions s ON u.subscription_id = s.id
                WHERE u.id = ?`, [userId], (err, updatedUser) => {
                    if (err) {
                        console.error('Error fetching updated user details:', err);  // Log the error
                        return res.status(500).json({ message: 'Error fetching updated user details.' });
                    }

                    // If the user is activated and has a price, update or insert balance
                    if (status === 'active' && updatedUser[0].price) {
                        const dailyIncome = updatedUser[0].price;

                        console.log('Checking if balance already exists for user:', userId); // Log check

                        // Check if the user already has a balance record
                        db.query('SELECT * FROM balance WHERE user_id = ? AND DATE(created_at) = CURDATE()', [userId], (err, balanceRecord) => {
                            if (err) {
                                console.error('Error checking existing balance record:', err); // Log error
                                return res.status(500).json({ message: 'Error checking balance record.' });
                            }

                            if (balanceRecord.length > 0) {
                                console.log('Balance record found, updating balance for user:', userId); // Log update
                                // If balance record exists, update it
                                db.query('UPDATE balance SET amount = ? WHERE user_id = ? AND DATE(created_at) = CURDATE()', [dailyIncome, userId], (err, updateResult) => {
                                    if (err) {
                                        console.error('Error updating balance:', err); // Log error
                                        return res.status(500).json({ message: 'Error updating balance.' });
                                    }

                                    // Calculate total balance for the user
                                    db.query('SELECT SUM(amount) AS total_balance FROM balance WHERE user_id = ?', [userId], (err, result) => {
                                        if (err) {
                                            console.error('Error calculating total balance:', err); // Log error
                                            return res.status(500).json({ message: 'Error calculating total balance.' });
                                        }

                                        const totalBalance = result[0].total_balance;
                                        return res.status(200).json({
                                            message: 'User status updated successfully and balance updated!',
                                            user: updatedUser[0], // Full user details with subscription
                                            total_balance: totalBalance
                                        });
                                    });
                                });
                            } else {
                                console.log('No existing balance record, inserting new balance entry for user:', userId); // Log insert
                                // Insert a new balance record for the user
                                db.query('INSERT INTO balance (user_id, amount) VALUES (?, ?)', [userId, dailyIncome], (err, result) => {
                                    if (err) {
                                        console.error('Error inserting into balance table:', err); // Log error
                                        return res.status(500).json({ message: 'Error updating balance.' });
                                    }

                                    // Calculate total balance for the user
                                    db.query('SELECT SUM(amount) AS total_balance FROM balance WHERE user_id = ?', [userId], (err, result) => {
                                        if (err) {
                                            console.error('Error calculating total balance:', err); // Log error
                                            return res.status(500).json({ message: 'Error calculating total balance.' });
                                        }

                                        const totalBalance = result[0].total_balance;
                                        return res.status(200).json({
                                            message: 'User status updated successfully and balance inserted!',
                                            user: updatedUser[0], // Full user details with subscription
                                            total_balance: totalBalance
                                        });
                                    });
                                });
                            }
                        });
                    } else {
                        return res.status(200).json({
                            message: 'User status updated successfully!',
                            user: updatedUser[0] // User data without subscription change
                        });
                    }
                });
        });
    });
});




// Add or modify a subscription
app.post('/subscription', verifyToken, (req, res) => {
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
app.get('/subscriptions', verifyToken, (req, res) => {
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
app.delete('/subscription/:id', verifyToken, (req, res) => {
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










/////////////////////////transactions request

// POST: Create a new transaction request (pending) with the restriction of one per day
app.post('/transaction', verifyToken, (req, res) => {
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
  
  
  






app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
