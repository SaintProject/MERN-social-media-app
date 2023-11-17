import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../models/User.js";

/* REGISTER USER */
export const register = async (req, res) => {
    try {
        const {
            firstName,
            lastName,
            email,
            password,
            picturePath,
            friends,
            location,
            occupation
        } = req.body;

        const saltRounds = 10;
        const salt = bcrypt.genSalt(saltRounds);
        const passwordToString = password.toString()
        const passwordHash = await bcrypt.hash(passwordToString, parseInt(salt));
        

        const newUser = User({
            firstName,
            lastName,
            email,
            password: passwordHash,
            picturePath,
            friends,
            location,
            occupation,
            viewedProfile: Math.floor(Math.random() * 10000),
            impressions: Math.floor(Math.random() * 10000),
        });
        const savedUser = await newUser.save();
        res.status(201).json(savedUser); // if the save went ok, we send the browswer status code 201 with the jsoned version of their profile
    } catch (err) {
        console.log(err);
        res.status(500).json({ error: err.message }); //if not, the we send code 500 with the error message
    }
}

/* LOGGING IN */
export const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email: email});
        if (!user) return res.status(400).json({ msg: "User does not exist."});

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ msg: "Invalid credentials."});

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);//if successful, generate token used for authentication, with the users id and a secret message
        delete user.password; //we then remove the password from the user object retrieved before sending it, for obvious reasons
        res.status(200).json({ token, user });// we send a response with a json object containing the token and the user object

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}