const User = require('../model/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const handleLogin = async (req, res) => {
	const cookies = req.cookies;
	const { user, pwd } = req.body;
	if (!user || !pwd)
		return res
			.status(400)
			.json({ message: 'Username and password are required.' });

	const foundUser = await User.findOne({ username: user }).exec();

	if (!foundUser) return res.sendStatus(401); // Unauthorized

	// evaluate password
	const match = await bcrypt.compare(pwd, foundUser.password);
	if (match) {
		const roles = Object.values(foundUser.roles).filter(Boolean); //eliminate any nulls
		// create JWTs
		const accessToken = jwt.sign(
			{
				UserInfo: { username: foundUser.username, roles: roles },
			},
			process.env.ACCESS_TOKEN_SECRET,
			{ expiresIn: '60s' }
		);
		const newRefreshToken = jwt.sign(
			{
				username: foundUser.username,
			},
			process.env.REFRESH_TOKEN_SECRET,
			{ expiresIn: '1h' }
		);

		let newRefreshTokenArray = !cookies?.jwt
			? foundUser.refreshToken
			: foundUser.refreshToken.filter((rt) => rt !== cookies.jwt);

		if (cookies?.jwt) {
			const refreshToken = cookies?.jwt;
			const foundToken = User.findOne({ refreshToken }).exec();

			// Detected refresh token reuse!
			if (!foundToken) {
				console.log('attempted refresh token reuse at login!')
				// clear out ALL previous refresh tokens
				newRefreshTokenArray = [];
			}

			res.clearCookie('jwt', {
				httpOnly: true,
				sameSite: 'None',
				secure: 'true',
			});
		}

		// Saving refresh token with current user
		foundUser.refreshToken = [...newRefreshTokenArray, newRefreshToken];
		const result = await foundUser.save();
		console.log(result);

		// Creates Secure Cookie with refresh token
		res.cookie('jwt', newRefreshToken, {
			httpOnly: true,
			secure: 'true',
			sameSite: 'None',
			maxAge: 24 * 60 * 60 * 1000,
		});

		// Send authorization roles and access token to user
		res.json({ accessToken });
	} else {
		res.sendStatus(401); // once again
	}
};

module.exports = { handleLogin };
