package staff.android.trust

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

data class Product(val id: String, val title: String, val price: String, val imageKey: String, val description: String)

object Catalog {
    val featured: List<Product> = listOf(
        Product("camera", "Camera", "₹12,999", "camera", "Keep the moments that matter. A compact camera with a familiar feel and room for your next story."),
        Product("tea", "Tea", "₹450", "tea", "A quiet ritual for your everyday. Carefully selected leaves with a bright and balanced character."),
        Product("bag", "Day bag", "₹2,490", "bag", "Carry the useful things. A durable everyday bag with comfortable handles and room for a little more."),
        Product("lamp", "Reading lamp", "₹1,990", "lamp", "A softer light for slower evenings. Make a comfortable corner for the stories you want to finish."),
        Product("mug", "Everyday mug", "₹690", "mug", "Your morning companion. A generous ceramic mug with a comfortable handle and a reassuring weight."),
        Product("headphones", "Headphones", "₹5,990", "headphones", "A little space for your sound. Comfortable listening for the commute, the desk and the walk home.")
    ).also(::validateFeatured)

    fun validateFeatured(products: List<Product>) {
        require(products.size == 6)
        require(products.map { it.id }.toSet().size == products.size)
        require(products.all { it.id.isNotBlank() && it.title.isNotBlank() && it.price.isNotBlank() && it.imageKey.isNotBlank() })
    }

    }
