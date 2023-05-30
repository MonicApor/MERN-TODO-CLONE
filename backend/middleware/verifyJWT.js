
const jwt = require("jsonwebtoken")

//since it is a middleware it should consist of next parameter
const verifyJWT = (req, res, next) => {
    //look at the header of the request and make sure that there is authorization header
    const authHeader = req.headers.authorization || req.headers.Authorization

    // the value should starts with bearer and followed by space and token (that is the format of the token)
    if(!authHeader?.startsWith('Bearer ')){
        return res.status(401).json({ message: "Unathorized" })
    }

    const token = authHeader.split(' ')[1] //get the token and split it since we dont need the bearer and space and it will be in the position 1

    //verify the tokem
    jwt.verify(
        token,
        process.env.ACCESS_TOKEN_SECRET,
        (err, decoded) => {
            if(err) return res.status(403).json({ message: 'Forbidden' }) // if there is error
            req.user = decoded.UserInfo.username; //set the req.user to the decoded info
            req.roles = decoded.UserInfo.roles; //set the req.user to the decoded info
            next();
        }
    )
}

module.exports = verifyJWT