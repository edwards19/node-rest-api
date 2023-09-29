const User = require('../model/User');
const jwt = require('jsonwebtoken');

const handleRefreshToken = async (req, res) => {
	const cookies = req.cookies;
	if (!cookies?.jwt) return res.sendStatus(401); // if we were to use res.status() that is chainable if we were sending a response after that
	const refreshToken = cookies.jwt;

	const foundUser = await User.findOne({refreshToken}).exec();

	if (!foundUser) return res.sendStatus(403); // Forbidden
	// evaluate jwt
	jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, decoded) => {
		const roles = Object.values(foundUser.roles);
		if (err || foundUser.username !== decoded.username) return res.sendStatus(403);
		const accessToken = jwt.sign(
			{
				UserInfo: {
					username: decoded.username,
					roles: roles,
				},
			},
			process.env.ACCESS_TOKEN_SECRET,
			{
				expiresIn: '60s',
			}
		);
		res.json({ roles, accessToken });
	});
};

module.exports = { handleRefreshToken };
