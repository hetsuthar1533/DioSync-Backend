const express = require("express");
const router = express.Router();
const {
    getStatesAndCitiesByCountry,
    getCountryByCityOrState
} = require("../controllers/DestinationController");

router.get("/country/:country", getStatesAndCitiesByCountry);

router.get("/city-or-state/:cityOrState", getCountryByCityOrState);

module.exports = router;
