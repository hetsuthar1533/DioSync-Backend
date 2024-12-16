const db = require("../db");

const getStatesAndCitiesByCountry = async (req, res) => {
    try {
        const { country } = req.params;

        const [statesCities] = await db.promise().query(
            "SELECT DISTINCT state, city FROM locations WHERE country = ?",
            [country]
        );

        if (statesCities.length === 0) {
            return res.status(404).json({
                success: false,
                message: `No states or cities found for country: ${country}`
            });
        }

        res.status(200).json({
            success: true,
            message: "States and cities fetched successfully",
            data: statesCities
        });
    } catch (error) {
        console.error("Failed to fetch states and cities", error);
        res.status(500).json({
            success: false,
            message: "Failed to fetch states and cities",
        });
    }
};

const getCountryByCityOrState = async (req, res) => {
    try {
        const { cityOrState } = req.params;

        const [countries] = await db.promise().query(
            "SELECT DISTINCT * FROM locations WHERE city = ? OR state = ?",
            [cityOrState, cityOrState]
        );

        if (countries.length === 0) {
            return res.status(404).json({
                success: false,
                message: `No country found for city or state: ${cityOrState}`
            });
        }

        res.status(200).json({
            success: true,
            message: "Country fetched successfully",
            data: countries
        });
    } catch (error) {
        console.error("Failed to fetch country", error);
        res.status(500).json({
            success: false,
            message: "Failed to fetch country",
        });
    }
};

module.exports = {
    getStatesAndCitiesByCountry,
    getCountryByCityOrState
};
