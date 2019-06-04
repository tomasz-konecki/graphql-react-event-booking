const bcrypt = require("bcryptjs");
const User = require("../../models/user");
const jwt = require("jsonwebtoken");

module.exports = {
  // resolver for the 'createUser' mutation
  createUser: async args => {
    try {
      const existingUser = await User.findOne({ email: args.userInput.email });
      if (existingUser) {
        throw new Error("User already exists.");
      }
      const hashedPassword = await bcrypt.hash(args.userInput.password, 12);

      const user = new User({
        email: args.userInput.email,
        password: hashedPassword
      });

      const result = await user.save();

      return { ...result._doc, password: null };
    } catch (err) {
      throw err;
    }
  },
  login: async ({ email, password }) => {
    const user = await User.findOne({ email: email });
    if (!user) {
      throw new Error("User does not exist!");
    }
    const isEqual = await bcrypt.compare(password, user.password); // comparing passwords
    if (!isEqual) {
      throw new Error("Password is incorrect!");
    }
    const token = jwt.sign(
      { userID: user.id, email: user.email },
      "somesupersecretkey",
      {
        expiresIn: "1h"
      }
    ); // this generates a token; the second argument is a String to hash the token (and later to validate it)
    return { userId: user.id, token: token, tokenExpiration: 1 };
  }
};
