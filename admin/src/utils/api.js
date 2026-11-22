import axios from "axios";

const BASE_URL =
    process.env.REACT_APP_BASE_URL || process.env.REACT_APP_API_URL || "http://localhost:4000";

if (!process.env.REACT_APP_BASE_URL) {
    console.warn(
        "REACT_APP_BASE_URL is not set in .env, using " + BASE_URL +
        ". Add REACT_APP_BASE_URL=http://localhost:4000 to .env and restart npm start."
    );
}

// Read the token on every request. Reading it once at page load would send a stale
// (empty) token for the whole session after the user signs in.
const authHeaders = () => {
    const token = localStorage.getItem("token");
    return token ? { Authorization: `Bearer ${token}` } : {};
};

const jsonConfig = () => ({
    headers: { "Content-Type": "application/json", ...authHeaders() },
});

// An expired or revoked session: clear it and send the person to sign in again.
const handleUnauthorized = (status) => {
    if (status === 401 && localStorage.getItem("token")) {
        localStorage.removeItem("token");
        localStorage.removeItem("user");
        if (window.location.pathname !== "/login") {
            window.location.href = "/login";
        }
    }
};

export const fetchDataFromApi = async (url) => {
    try {
        const { data } = await axios.get(BASE_URL + url, jsonConfig());
        return data;
    } catch (error) {
        handleUnauthorized(error?.response?.status);
        // Log the real reason (network/CORS, 401, 403, 500...) and return an empty list so a
        // failed request cannot crash pages that call .map() on the result.
        console.error(`GET ${url} failed:`, error?.response?.status || error?.message, error?.response?.data || "");
        return [];
    }
};

export const postData = async (url, formData) => {
    try {
        const response = await fetch(BASE_URL + url, {
            method: "POST",
            headers: jsonConfig().headers,
            body: JSON.stringify(formData),
        });

        handleUnauthorized(response.status);
        return await response.json();
    } catch (error) {
        console.error("Error:", error);
    }
};

export const editData = async (url, updatedData) => {
    try {
        const { data } = await axios.put(`${BASE_URL}${url}`, updatedData, jsonConfig());
        return data;
    } catch (error) {
        handleUnauthorized(error?.response?.status);
        if (error?.response?.data?.msg) error.message = error.response.data.msg;
        throw error;
    }
};

export const deleteData = async (url) => {
    try {
        const { data } = await axios.delete(`${BASE_URL}${url}`, jsonConfig());
        return data;
    } catch (error) {
        handleUnauthorized(error?.response?.status);
        if (error?.response?.data?.msg) error.message = error.response.data.msg;
        throw error;
    }
};

// Multipart upload: let the browser set the Content-Type (with its boundary).
export const uploadImage = async (url, formData) => {
    try {
        const { data } = await axios.post(BASE_URL + url, formData, { headers: authHeaders() });
        return data;
    } catch (error) {
        handleUnauthorized(error?.response?.status);
        if (error?.response?.data?.msg) error.message = error.response.data.msg;
        throw error;
    }
};

export const deleteImages = async (url) => {
    try {
        const { data } = await axios.delete(`${BASE_URL}${url}`, jsonConfig());
        return data;
    } catch (error) {
        handleUnauthorized(error?.response?.status);
        if (error?.response?.data?.msg) error.message = error.response.data.msg;
        throw error;
    }
};
