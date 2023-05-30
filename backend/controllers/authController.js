const User = require("../models/User")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")


// @desc Login
// @route POST /auth
// @access Public
const login = async (req, res) => {
    // when user login in get the username and password
    const { username, password } = req.body

    //check if all fields are inputted
    if(!username || !password) {
        return res.status(400).json({ message: "All fields are required "});
    }

    const foundUser = await User.findOne({username}).exec()

    //check if username exist or if the user is active
    if(!foundUser || !foundUser.active){
        return res.status(401).json({ message: "Unathorized User" });
    }

    //check if the password match
    const match = await bcrypt.compare(password, foundUser.password);
    if(!match){
        return res.status(401).json({ message: "Unauthorized" });
    }

    //create the access token and secure http cookie

    //jwt.sign contains object userinfo and the access token will expires in 15m
    const accessToken = jwt.sign(
        {
            "UserInfo" : {
                "username": foundUser.username,
                "roles": foundUser.roles
            }
        },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: '15m'}
    )

    const refreshToken = jwt.sign(
        { "username": foundUser.username },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn : '7d'}
    )
    
    //create a secure cookie with refresh token
    res.cookie('jwt', refreshToken, {
        httpOnly: true, //accessible only to web server but still can be access in mobile app
        secure: true, // https
        sameSite: 'None', //cross-site cookie
        maxAge: 7 * 24 * 60 * 60 * 1000 //cookie expiry: set to match rT (7days,24hrs,60min,60sec,1000miliseconds)
    })

    //send accessToken containing username and roles
    res.json( { accessToken })

}

// @desc refresh
// @route GET /auth/refresh
// @access Public - because access token has expired
const refresh = ( req, res) => {
    //get the created cookie at the top
    const cookies = req.cookies
    // check if cookie exist cookie.jwt
    if(!cookies?.jwt) return res.status(401).json({ message: "Unathorized" })

    // if exist set the refreshToken to cookies
    const refreshToken = cookies.jwt

    //used jwt verify dependency to verify the token
    jwt.verify(
        //pass the refreshToken the secret key 
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        async (err, decoded) => {
            //the asynchandler check if there is error and it will pass the arg err
            if(err) return res.status(403).json({ message: "Forbidden" });
            //check if there is a user from the decoded username inside the refresh token
            const foundUser = await User.findOne({ username: decoded.username}).exec()
            //check if user exist
            if(!foundUser) return res.status(401).json({ message: "Unathorized"})

            //create a new accessToken with the username and role and 
            const accessToken = jwt.sign(
                {
                    "UserInfo" : {
                        "username": foundUser.username,
                        "roles": foundUser.roles
                    },
                },
                process.env.ACCESS_TOKEN_SECRET,
                { expiresIn : '15m'}
            )
            res.json({ accessToken })
        }
    )
}

// @desc Login
// @route POST /auth / logout
// @access Public - just to clear cookie if exist
const logout = async (req, res) => {
     //get the created cookie at the top
     const cookies = req.cookies
     // check if cookie exist cookie.jwt
     if(!cookies?.jwt) return res.sendStatus(204) //No Content 204 the request is successful but there is no content
     res.clearCookie('jwt', { httpOnly: true, secure: true, sameSite: 'None'})
     res.json({ message: "Cookie cleared" })

}

module.exports = { login, refresh, logout}