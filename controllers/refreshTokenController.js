const User = require('../model/User');
const jwt = require('jsonwebtoken');

const handleRefreshToken = async (req, res) => {
	const cookies = req.cookies;
	if (!cookies?.jwt) return res.sendStatus(401); // if we were to use res.status() that is chainable if we were sending a response after that
	const refreshToken = cookies.jwt;
	// delete the cookie after receiving it since we're creating a new one
	res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: 'true' });

	const foundUser = await User.findOne({ refreshToken }).exec();

	// Detected refresh token reuse!
	if (!foundUser) {
		jwt.verify(
			refreshToken,
			process.env.REFRESH_TOKEN_SECRET,
			async (err, decoded) => {
				if (err) return res.sendStatus(403); // Forbidden
				const hackedUser = await User.findOne({
					username: decoded.username,
				}).exec();
				// delete all refresh tokens for each device used by the user to log in
				hackedUser.refreshToken = [];
				const result = hackedUser.save();
				console.log(result);
			}
		);
		return res.sendStatus(403); // Forbidden
	}

	const newRefreshTokenArray = foundUser.refreshToken.filter(
		(rt) => rt !== refreshToken
	);

	// evaluate jwt
	jwt.verify(
		refreshToken,
		process.env.REFRESH_TOKEN_SECRET,
		async (err, decoded) => {
			if (err) {
				foundUser.refreshToken = [...newRefreshTokenArray];
				const result = await foundUser.save();
			}
			if (err || foundUser.username !== decoded.username) {
				return res.sendStatus(403);
			}

			const roles = Object.values(foundUser.roles);

			// Refresh token was still valid
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

			const newRefreshToken = jwt.sign(
				{
					username: foundUser.username,
				},
				process.env.REFRESH_TOKEN_SECRET,
				{ expiresIn: '1h' }
			);
			// Saving refresh token with current user
			foundUser.refreshToken = [...newRefreshTokenArray, newRefreshToken];
			const result = await foundUser.save();

			// Creates Secure Cookie with refresh token
			res.cookie('jwt', newRefreshToken, {
				httpOnly: true,
				secure: 'true',
				sameSite: 'None',
				maxAge: 24 * 60 * 60 * 1000,
			});

			res.json({ accessToken });
		}
	);
};

module.exports = { handleRefreshToken };
