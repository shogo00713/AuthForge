import { RESOURCE_SERVER_URL } from "../config";

export default async function fetchResources(token: string) {
    const response = await fetch(`${RESOURCE_SERVER_URL}/resources`, {
        method: "GET",
        headers: {
            "Authorization": "Bearer " + token
        }
    });
    if (response.status === 401) {
        return null;
    }
    const data = await response.json();
    return data;
}