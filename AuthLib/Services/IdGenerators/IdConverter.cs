namespace AuthLib.Services.IdGenerators
{
    internal static class IdConverter<TKey> where TKey : IEquatable<TKey>
    {
        public static TKey FromString(string id)
        {
            if (string.IsNullOrWhiteSpace(id))
                throw new ArgumentException("ID cannot be null or empty.", nameof(id));

            var type = typeof(TKey);

            try
            {
                if (type == typeof(string))
                {
                    return (TKey)(object)id;
                }
                else if (type == typeof(Guid))
                {
                    return (TKey)(object)Guid.Parse(id);
                }
                else if (type == typeof(int))
                {
                    return (TKey)(object)int.Parse(id);
                }
                else if (type == typeof(long))
                {
                    return (TKey)(object)long.Parse(id);
                }
                else
                {
                    throw new NotSupportedException($"ID conversion for type {type.Name} is not supported. " +
                        $"Supported types are: string, Guid, int, long.");
                }
            }
            catch (FormatException ex)
            {
                throw new ArgumentException($"Invalid ID format for type {type.Name}: '{id}'", nameof(id), ex);
            }
            catch (OverflowException ex)
            {
                throw new ArgumentException($"ID value '{id}' is out of range for type {type.Name}", nameof(id), ex);
            }
        }

        public static string ToString(TKey id)
        {
            if (id == null)
                throw new ArgumentNullException(nameof(id));

            return id.ToString() ?? throw new InvalidOperationException($"Failed to convert ID of type {typeof(TKey).Name} to string.");
        }
    }
}
