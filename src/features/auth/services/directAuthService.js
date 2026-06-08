// Direct Authentication Service (No Firebase)
// Handles authentication using localStorage only

import { logAction } from '../../../shared/utils/auditLogger';

const USERS_STORAGE_KEY = 'rehab_ai_users';
const CURRENT_USER_KEY = 'rehab_ai_current_user';
const SESSION_KEY = 'rehab_ai_session';

/**
 * Simple hash function for password (NOT cryptographically secure - for demo purposes only)
 * In production, this should be done server-side
 */
const hashPassword = (password) => {
  let hash = 0;
  for (let i = 0; i < password.length; i++) {
    const char = password.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32-bit integer
  }
  return 'hash_' + Math.abs(hash).toString(36);
};

/**
 * Get all users from localStorage
 */
const getAllUsers = () => {
  try {
    const usersJson = localStorage.getItem(USERS_STORAGE_KEY);
    return usersJson ? JSON.parse(usersJson) : {};
  } catch (error) {
    console.error('[DirectAuthService] Error reading users:', error);
    return {};
  }
};

/**
 * Save users to localStorage
 */
const saveAllUsers = (users) => {
  try {
    localStorage.setItem(USERS_STORAGE_KEY, JSON.stringify(users));
  } catch (error) {
    console.error('[DirectAuthService] Error saving users:', error);
    throw new Error('Failed to save user data');
  }
};

/**
 * Get current session user
 */
const getSessionUser = () => {
  try {
    const sessionJson = localStorage.getItem(SESSION_KEY);
    if (!sessionJson) return null;
    const session = JSON.parse(sessionJson);
    // Check if session is still valid (24 hours)
    if (Date.now() - session.loginTime > 24 * 60 * 60 * 1000) {
      localStorage.removeItem(SESSION_KEY);
      return null;
    }
    return session.user;
  } catch (error) {
    console.error('[DirectAuthService] Error reading session:', error);
    return null;
  }
};

/**
 * Set current session user
 */
const setSessionUser = (user) => {
  try {
    localStorage.setItem(SESSION_KEY, JSON.stringify({
      user,
      loginTime: Date.now()
    }));
  } catch (error) {
    console.error('[DirectAuthService] Error saving session:', error);
    throw new Error('Failed to save session');
  }
};

/**
 * Generate a unique user ID
 */
const generateUserId = () => {
  return 'user_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
};

/**
 * Sign in with email and password
 */
export const loginWithEmail = async (email, password, userType = 'patient') => {
  try {
    if (!email || !password) {
      throw new Error('Email and password are required');
    }

    const users = getAllUsers();
    const userEntry = Object.values(users).find(
      u => u.email.toLowerCase() === email.toLowerCase() && u.userType === userType
    );

    if (!userEntry) {
      throw new Error('No account found with this email and user type');
    }

    const passwordHash = hashPassword(password);
    if (userEntry.passwordHash !== passwordHash) {
      throw new Error('Incorrect password');
    }

    // Create session
    const userData = {
      uid: userEntry.uid,
      email: userEntry.email,
      name: userEntry.name,
      userType: userEntry.userType,
      createdAt: userEntry.createdAt,
    };

    setSessionUser(userData);
    
    console.log('[DirectAuthService] Login successful:', userData);
    await logAction(userEntry.uid, 'LOGIN', { method: 'email', email });

    return {
      user: { uid: userEntry.uid, email: userEntry.email },
      userData
    };
  } catch (error) {
    console.error('[DirectAuthService] Login error:', error);
    throw error;
  }
};

/**
 * Sign up with email and password
 */
export const signupWithEmail = async (email, password, name, userType) => {
  try {
    if (!email || !password || !name) {
      throw new Error('Email, password, and name are required');
    }

    if (password.length < 6) {
      throw new Error('Password should be at least 6 characters');
    }

    const users = getAllUsers();
    
    // Check if email already exists for this user type
    const emailExists = Object.values(users).some(
      u => u.email.toLowerCase() === email.toLowerCase() && u.userType === userType
    );

    if (emailExists) {
      throw new Error('This email is already registered for this user type');
    }

    // Create new user
    const uid = generateUserId();
    const passwordHash = hashPassword(password);
    const createdAt = new Date().toISOString();

    users[uid] = {
      uid,
      email: email.toLowerCase(),
      name,
      userType,
      passwordHash,
      createdAt,
      updatedAt: createdAt,
      // Additional patient fields
      ...(userType === 'patient' && {
        injuryType: '',
        rehabPhase: 'Initial',
        currentPainLevel: 5,
        doctorId: null
      }),
      // Additional doctor fields
      ...(userType === 'doctor' && {
        specialization: '',
        licenseNumber: '',
        clinic: ''
      })
    };

    saveAllUsers(users);

    console.log('[DirectAuthService] Signup successful:', uid);
    await logAction(uid, 'SIGNUP', { method: 'email', email, userType });

    return {
      user: { uid, email },
      userData: {
        uid,
        email,
        name,
        userType,
        createdAt
      }
    };
  } catch (error) {
    console.error('[DirectAuthService] Signup error:', error);
    throw error;
  }
};

/**
 * Update user profile
 */
export const updateUserProfile = async (uid, data) => {
  try {
    const users = getAllUsers();
    if (!users[uid]) {
      throw new Error('User not found');
    }

    // Don't allow updating userType
    const { userType: _, ...updateData } = data;

    users[uid] = {
      ...users[uid],
      ...updateData,
      updatedAt: new Date().toISOString()
    };

    saveAllUsers(users);

    // Update session if this is the current user
    const currentUser = getSessionUser();
    if (currentUser && currentUser.uid === uid) {
      const updatedUser = { ...currentUser, ...updateData };
      setSessionUser(updatedUser);
    }

    console.log('[DirectAuthService] User profile updated:', uid);
    await logAction(uid, 'UPDATE_PROFILE', { fields: Object.keys(updateData) });

    return { success: true };
  } catch (error) {
    console.error('[DirectAuthService] Update profile error:', error);
    throw error;
  }
};

/**
 * Change password
 */
export const changePassword = async (uid, oldPassword, newPassword) => {
  try {
    const users = getAllUsers();
    if (!users[uid]) {
      throw new Error('User not found');
    }

    const oldPasswordHash = hashPassword(oldPassword);
    if (users[uid].passwordHash !== oldPasswordHash) {
      throw new Error('Current password is incorrect');
    }

    if (newPassword.length < 6) {
      throw new Error('New password should be at least 6 characters');
    }

    const newPasswordHash = hashPassword(newPassword);
    users[uid].passwordHash = newPasswordHash;
    users[uid].updatedAt = new Date().toISOString();

    saveAllUsers(users);

    console.log('[DirectAuthService] Password changed:', uid);
    await logAction(uid, 'CHANGE_PASSWORD', {});

    return { success: true };
  } catch (error) {
    console.error('[DirectAuthService] Change password error:', error);
    throw error;
  }
};

/**
 * Reset password (in production, this would send an email)
 */
export const resetPassword = async (email) => {
  try {
    const users = getAllUsers();
    const userEntry = Object.values(users).find(
      u => u.email.toLowerCase() === email.toLowerCase()
    );

    if (!userEntry) {
      // Don't reveal if email exists for security reasons
      throw new Error('If this email exists in our system, password reset instructions have been sent');
    }

    // In a real app, you'd send an email here with a reset link
    // For now, just generate a temp password
    const tempPassword = Math.random().toString(36).substring(2, 8);
    const tempPasswordHash = hashPassword(tempPassword);

    users[userEntry.uid].passwordHash = tempPasswordHash;
    users[userEntry.uid].updatedAt = new Date().toISOString();
    saveAllUsers(users);

    console.log('[DirectAuthService] Password reset requested for:', email);
    
    // In production: send email with reset instructions
    // For now, show the temp password to user (NOT SECURE - only for demo)
    return {
      success: true,
      tempPassword, // In production, this would be sent via email
      message: `Temporary password: ${tempPassword} (change it after login)`
    };
  } catch (error) {
    console.error('[DirectAuthService] Password reset error:', error);
    throw error;
  }
};

/**
 * Logout current user
 */
export const logout = async () => {
  try {
    const currentUser = getSessionUser();
    if (currentUser) {
      await logAction(currentUser.uid, 'LOGOUT', {});
    }
    localStorage.removeItem(SESSION_KEY);
    console.log('[DirectAuthService] Logout successful');
    return { success: true };
  } catch (error) {
    console.error('[DirectAuthService] Logout error:', error);
    throw error;
  }
};

/**
 * Get current user from session
 */
export const getCurrentUser = () => {
  return getSessionUser();
};

/**
 * Subscribe to auth state changes
 * Returns a function to unsubscribe
 */
export const onAuthChange = (callback) => {
  // Initial check
  const currentUser = getSessionUser();
  if (currentUser) {
    callback({ user: { uid: currentUser.uid, email: currentUser.email }, userData: currentUser });
  } else {
    callback(null);
  }

  // Listen for storage changes (handles multi-tab logout/login)
  const handleStorageChange = (e) => {
    if (e.key === SESSION_KEY) {
      const newSession = e.newValue;
      if (newSession) {
        const session = JSON.parse(newSession);
        callback({ user: { uid: session.user.uid, email: session.user.email }, userData: session.user });
      } else {
        callback(null);
      }
    }
  };

  window.addEventListener('storage', handleStorageChange);

  return () => {
    window.removeEventListener('storage', handleStorageChange);
  };
};

/**
 * Demo credentials for quick testing
 */
export const DEMO_CREDENTIALS = {
  doctor: {
    email: 'doctor@demo.com',
    password: 'Demo123!',
  },
  patient: {
    email: 'rajesh@demo.com',
    password: 'Demo123!',
  },
  admin: {
    email: 'admin@demo.com',
    password: 'Demo123!',
  },
};

/**
 * Initialize demo users
 */
export const initializeDemoUsers = () => {
  const users = getAllUsers();
  
  // Only initialize if no users exist
  if (Object.keys(users).length === 0) {
    const demoUsers = {
      [generateUserId()]: {
        uid: 'demo_doctor_1',
        email: DEMO_CREDENTIALS.doctor.email,
        name: 'Dr. Sarah Smith',
        userType: 'doctor',
        passwordHash: hashPassword(DEMO_CREDENTIALS.doctor.password),
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        specialization: 'Physical Therapy',
        licenseNumber: 'PT-12345',
        clinic: 'Heal-gorithms Clinic'
      },
      [generateUserId()]: {
        uid: 'demo_patient_1',
        email: DEMO_CREDENTIALS.patient.email,
        name: 'Rajesh Kumar',
        userType: 'patient',
        passwordHash: hashPassword(DEMO_CREDENTIALS.patient.password),
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        injuryType: 'Knee Injury',
        rehabPhase: 'Mid',
        currentPainLevel: 5,
        doctorId: 'demo_doctor_1'
      },
      [generateUserId()]: {
        uid: 'demo_admin_1',
        email: DEMO_CREDENTIALS.admin.email,
        name: 'System Admin',
        userType: 'admin',
        passwordHash: hashPassword(DEMO_CREDENTIALS.admin.password),
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      }
    };

    saveAllUsers(demoUsers);
    console.log('[DirectAuthService] Demo users initialized');
  }
};

// Initialize demo users when service loads
initializeDemoUsers();
