const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');

router.get('/details', userController.getDetails);
router.put('/update', userController.updateInfo);
router.delete('/delete', userController.deleteInfo);

module.exports = router;
